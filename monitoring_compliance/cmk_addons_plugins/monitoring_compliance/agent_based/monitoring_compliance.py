#!/usr/bin/env python3
# Checkmk Monitoring Compliance
# Agent-based check plug-in (Check API v2)
#
# Determines, per host, which subsystems are installed/running but NOT yet
# monitored, even though Checkmk would be able to monitor them.
#
#   - WARN: present but not running, not monitored
#   - CRIT: present and running,     not monitored
#
# Detection is no longer based on a static application list. Instead every
# data source contributes typed "capabilities" (type + name). Capabilities are
# correlated to the check plug-ins available on the site (by a normalized name
# token + alias table), so any program whose name matches an available plug-in
# is detected automatically. All capabilities are additionally written to a
# persistent, deduplicated Capability Database that grows over time.
#
# Detection sources:
#   1. Existing agent sections   -> which of the consumed sections are present
#   2. systemd units             -> via agent plug-in / built-in section
#   3. Processes (ps / ps_lnx)   -> running programs
#   4. Host labels               -> via the special agent (Livestatus)
#   5. HW/SW inventory packages  -> via the special agent (inventory tree)
#   + installed packages         -> lnx_packages / win_reg_uninstall / agent

import json
import os
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
)

# ---------------------------------------------------------------------------
# Capability types
# ---------------------------------------------------------------------------

T_SECTION = "agent_section"
T_SYSTEMD = "systemd_unit"
T_SERVICE = "service"
T_PROCESS = "process"
T_LABEL = "host_label"
T_INV_PACKAGE = "inv_package"
T_PACKAGE = "package"

RUNNING_TYPES = {T_PROCESS, T_SYSTEMD, T_SERVICE, T_SECTION}
INSTALLED_TYPES = {T_PACKAGE, T_INV_PACKAGE}

# Some subsystems are kernel/library features rather than a running service:
# the package (and any always-on boot hook units, see
# SYSTEMD_ALWAYS_ON_UNITS below) can be present on virtually every host of a
# distro family without the feature ever being *used*. For these tokens,
# package/inventory presence alone is not treated as evidence of actual use;
# we additionally require corroborating evidence from the already-collected
# "df" section (mounted filesystems), which every host reports anyway - no
# extra agent plug-in needed. If that evidence is missing, the capability is
# dropped entirely (not just downgraded), matching what a human investigating
# the host would conclude ("installed but never touched").
# "mssql" is included here too, but with a different rationale: unlike the
# storage/cluster features above, a real SQL Server *engine* install is a
# legitimate WARN ("present, not running") even while stopped - the problem
# is that *installed-only* evidence for "mssql" keeps coming from packages
# that are not the engine at all (SQL Server Compact, ODBC/OLE DB drivers,
# SSMS, ...; see EVIDENCE_EXCLUDE) and new client-only package name variants
# keep showing up faster than they can be excluded one by one. Requiring the
# Windows "services" section to show an actual "MSSQL*"-prefixed service
# (running or not) as corroboration - see _usage_evidence() below -
# means only real Microsoft SQL Server engine installs (which always
# register such a service, even when stopped) can ever trigger this
# recommendation at all, independent of how creatively named some bundled
# driver/tool package turns out to be.
TOKENS_REQUIRE_USAGE_EVIDENCE: frozenset[str] = frozenset({"lvm", "zfs", "corosync", "dmraid", "mssql", "iis"})

# Some packages/inventory hits are client-only libraries/tools that ship as a
# dependency of countless other packages and say nothing about whether the
# corresponding *server* is installed (e.g. "mysql-common"/"mariadb-common"
# pull in for any package that merely links against the client library).
# Package/inv_package names matching these per-token patterns are therefore
# not counted as installation evidence; a real server package (e.g.
# "mariadb-server", "mysql-server") or running evidence (systemd unit/process
# via ALIASES, e.g. "mariadbd"/"mysqld") is still required.
# Some packages/inventory hits and even systemd units/processes are
# client-only components that ship for every host regardless of whether the
# corresponding *server* is present (e.g. "mysql-common"/"mariadb-common"
# pull in for any package that merely links against the client library; NUT's
# "nut-client"/"nut-monitor" client-side UPS-status monitor commonly run on
# any host regardless of whether a local NUT *server* (upsd) is configured).
# Package/inv_package/systemd-unit/process names matching these per-token
# patterns are therefore not counted as installation or running evidence; a
# real server package/unit/process (e.g. "mariadb-server"/"mysqld",
# "nut-server"/"nut-driver@*"/"upsd") is still required.
EVIDENCE_EXCLUDE: dict[str, "re.Pattern[str]"] = {
    "mysql": re.compile(
        r"(?:^|[-_])(?:common|client|clients)(?:[-_]|$)|^lib(?:mysqlclient|mariadb)\d*"
        r"|^libdbd-mysql-perl$"
        # Driver/connector packages (ODBC, JDBC, .NET connector, Python
        # connector, etc.) are client-side application connectivity
        # libraries, not the database server, and ship on any host that
        # merely talks to a MySQL/MariaDB server elsewhere.
        r"|connector|odbc|jdbc",
        re.IGNORECASE,
    ),
    "nut": re.compile(
        r"^nut$|^nut-client(\.(service|path))?$|^nut-monitor(\.service)?$",
        re.IGNORECASE,
    ),
    "apache": re.compile(
        r"^apache2-utils$|^apache2-bin$|^httpd-tools$",
        re.IGNORECASE,
    ),
    # "Azure" alone is too generic a vendor token to trust blindly (any
    # locally installed developer/admin tool bearing the Azure name would
    # otherwise "prove" an Azure AD sync or monitoring agent installation).
    # Client-side tooling that a host may have installed regardless of any
    # Azure AD/agent role (Azure Data Studio, Azure CLI, Azure PowerShell
    # module, Azure Storage Explorer) is therefore excluded here; real
    # agent/connector packages (e.g. "Azure AD Connect", "Azure Connected
    # Machine Agent", "Azure Monitor Agent") are still accepted as evidence.
    "azure": re.compile(
        r"data studio|storage explorer|\bcli\b|powershell",
        re.IGNORECASE,
    ),
    # "SQL Server" client-side driver/tooling packages (ODBC/OLE DB
    # providers, SSMS, SqlClient/ADO.NET libraries), "SQL Server Compact"
    # (SQLCE), demo databases, the SQL Server Browser service package, etc.
    # need no name-pattern exclude here at all: see the generic
    # INSTALLED_TYPES filter below (applied to every
    # TOKENS_REQUIRE_USAGE_EVIDENCE token, not just "mssql") - since none of
    # these are ever the actual running-service evidence, they are dropped
    # from "sources" generically by type rather than enumerated by name,
    # which would otherwise need constant upkeep as new client-package
    # name variants keep showing up.
    # The available plug-ins here (citrix_controller, citrix_controller_
    # licensing, citrix_controller_registered) all monitor a Citrix
    # Delivery Controller server role. A huge number of "Citrix ..."
    # packages, however, are shipped on VDAs (Virtual Delivery Agent =
    # the managed *client* desktops/servers) or are end-user Workspace/
    # Receiver client installs - they prove a Citrix-managed endpoint,
    # never a Delivery Controller. Exclude that VDA/client-side tooling
    # so it stops falsely "proving" a Controller install; a real
    # Controller/Studio/core package is still accepted as evidence.
    "citrix": re.compile(
        r"vda\b|virtual delivery agent|receiver|workspace app|ica client"
        r"|hdx|browser content redirection|diagnostics facility"
        r"|group policy client-side extension|profile management|profilverwaltung"
        r"|director vda plugin|print(?:er)? driver|universal print|druckclient|druckertreiber"
        r"|mcs\b|machine creation services|telemetry service|casting|desktop lock"
        r"|app protection|user profile",
        re.IGNORECASE,
    ),
}
# Backwards-compatible alias (kept in case other code/tests reference the old
# name); both names point at the same dict.
PACKAGE_EVIDENCE_EXCLUDE = EVIDENCE_EXCLUDE

# ---------------------------------------------------------------------------
# Seed knowledge: aliases (raw token -> canonical token), nice titles, hints.
# This is only used to improve naming/precision; correlation itself works
# generically against the plug-ins available on the site.
# ---------------------------------------------------------------------------

ALIASES: dict[str, str] = {
    "mariadb": "mysql", "mariadbd": "mysql", "mysqld": "mysql", "mysql": "mysql",
    "postgresql": "postgres", "postgres": "postgres", "postmaster": "postgres",
    "httpd": "apache", "apache2": "apache", "apache": "apache",
    "nginx": "nginx",
    "redis": "redis",
    "mongod": "mongodb", "mongodb": "mongodb",
    "dockerd": "docker", "containerd": "docker", "docker": "docker",
    "rabbitmq": "rabbitmq",
    "elasticsearch": "elasticsearch",
    "haproxy": "haproxy",
    "postfix": "postfix",
    "nfsd": "nfsexports",
    "catalina": "jolokia", "tomcat": "jolokia", "jolokia": "jolokia",
    "ora": "oracle", "oracle": "oracle", "pmon": "oracle",
    "sqlservr": "mssql", "mssql": "mssql",
    "w3wp": "iis", "inetinfo": "iis", "iis": "iis",
    "msexchange": "msexch", "edgetransport": "msexch", "exchange": "msexch",
    "pdns": "powerdns", "powerdns": "powerdns",
}

TITLES: dict[str, str] = {
    "mysql": "MySQL / MariaDB", "postgres": "PostgreSQL",
    "apache": "Apache HTTP Server", "nginx": "NGINX", "redis": "Redis",
    "mongodb": "MongoDB", "docker": "Docker", "rabbitmq": "RabbitMQ",
    "elasticsearch": "Elasticsearch", "haproxy": "HAProxy", "postfix": "Postfix",
    "nfsexports": "NFS Server", "jolokia": "Java / Tomcat (Jolokia)",
    "oracle": "Oracle Database", "mssql": "Microsoft SQL Server",
    "iis": "Microsoft IIS", "msexch": "Microsoft Exchange",
    "powerdns": "PowerDNS",
    "windhcp": "Windows DHCP Server",
}

HINTS: dict[str, str] = {
    "mysql": "Deploy the 'mk_mysql' agent plug-in, then run service discovery.",
    "postgres": "Deploy the 'mk_postgres' agent plug-in, then run discovery.",
    "apache": "Deploy the 'mk_apache' agent plug-in (requires mod_status).",
    "nginx": "Enable stub_status and deploy the 'nginx_status' agent plug-in.",
    "redis": "Deploy the 'mk_redis' agent plug-in, then run discovery.",
    "mongodb": "Deploy the 'mk_mongodb' agent plug-in, then run discovery.",
    "docker": "Deploy the 'mk_docker' agent plug-in, then run discovery.",
    "rabbitmq": "Deploy the 'mk_rabbitmq' agent plug-in, then run discovery.",
    "elasticsearch": "Configure the 'Elasticsearch' special agent.",
    "haproxy": "Enable the stats socket and deploy the 'haproxy' plug-in.",
    "postfix": "Deploy the 'mk_postfix' agent plug-in, then run discovery.",
    "nfsexports": "Deploy the agent plug-in for NFS exports.",
    "jolokia": "Integrate Jolokia and deploy the 'mk_jolokia' agent plug-in.",
    "oracle": "Deploy the 'mk_oracle' agent plug-in, then run discovery.",
    "mssql": "Deploy the 'mssql.vbs' agent plug-in, then run discovery.",
    "iis": "Deploy the agent plug-in for IIS application pools.",
    "msexch": "Deploy the Exchange counter plug-ins, then run discovery.",
    "powerdns": "Deploy the 'powerdns' agent plug-in, then run discovery.",
    "windhcp": "Deploy the 'win_dhcp_pools' agent plug-in, then run discovery.",
}


# Generic Checkmk plug-in tokens that should never be treated as an
# "application" (avoids noise from base OS checks).
STOP_TOKENS = {
    "cpu", "mem", "memory", "df", "tcp", "udp", "uptime", "kernel", "mounts",
    "mount", "systemd", "diskstat", "lnx", "ps", "mkeventd", "check", "cmk",
    "livestatus", "omd", "chrony", "ntp", "cron", "ssh", "sshd", "users",
    "threads", "vmstat", "swap", "fileinfo", "logwatch", "md", "multipath",
    "tcpconn", "netif", "if", "interfaces", "hr", "snmp",
    # Generic name fragments that happen to be the leading token of a very
    # specific hardware/vendor plug-in (e.g. "intel_true_scale_chassis_temp")
    # but say nothing meaningful when they show up as a package/process name
    # fragment (e.g. package "intel-microcode"). Without this, the naive
    # leading-token tokenizer used on both sides collides purely by
    # coincidence and reports a false "available plug-in".
    "intel",
    # "watchdog" is the leading token of both the systemd hardware-watchdog
    # multiplexer ("watchdog-mux.service", part of the base "watchdog"
    # package, unrelated to any monitored subsystem) and the unrelated
    # environmental-sensor check plug-ins "watchdog_sensors*" (Watchdog Inc.
    # weather-station hardware). Pure leading-token coincidence, not a
    # covering plug-in relationship - same class of false positive as
    # "intel" above.
    "watchdog",
    # "iptables" is not a token-collision case like the ones above - the
    # match against the "iptables" check plug-in is genuine. It is excluded
    # anyway because the iptables package/kernel netfilter tooling ships as
    # a standard part of virtually every Linux distribution regardless of
    # whether it is actually used for firewalling on a given host, so mere
    # presence carries no real compliance signal (same rationale class as
    # TOKENS_REQUIRE_USAGE_EVIDENCE, but there is no cheap usage evidence
    # available for it from already-collected agent sections, so it is
    # dropped outright instead).
    "iptables",
    # "mtr" (network diagnostics tool, combines traceroute+ping) is a
    # genuine, real package match too, but the check_mk 'mtr' plug-in
    # requires a deliberate manual setup (a per-host list of static target
    # hosts/IPs to continuously trace, configured in a dedicated agent
    # bakery rule) that is far too specific a use case to flag as a missing
    # default for every host that merely has the mtr package installed
    # (e.g. as a troubleshooting tool, unrelated to being monitored via it).
    "mtr",
    # "site" is the leading token of the Checkmk-bundled "site_object_counts"
    # plug-in (mk_site_object_counts - counts objects of a *Checkmk site*
    # itself, rolled out via its own dedicated agent bakery rule) but also
    # the leading token of countless unrelated "site-*" packages (e.g. a
    # web server's "site-config" package for a vhost). Pure leading-token
    # coincidence, not a covering plug-in relationship - same class of
    # false positive as "intel"/"watchdog" above.
    "site",
    # "security" is the leading token of the environmental-sensor check
    # plug-ins "security_master"/"security_master_humidity"/
    # "security_master_temp" (Security Master brand hardware sensors), but
    # is also the leading word of countless unrelated Windows update /
    # inventory package display names (e.g. "Security Update for Microsoft
    # Office 2010 (KB2553313) 32-Bit Edition"). Pure leading-token
    # coincidence, not a covering plug-in relationship - same class of
    # false positive as "intel"/"watchdog"/"site" above.
    "security",
}

# Substring / word signatures for matching verbose names (especially Windows
# display names and services). Checked in order before generic tokenization.
# Each tuple is (pattern, canonical token). More specific patterns come first.
_SIGNATURES_RAW: tuple[tuple[str, str], ...] = (
    (r"microsoft sql server", "mssql"),
    (r"\bsql\s*server\b", "mssql"),
    (r"\bmssql\b", "mssql"),
    (r"sqlservr", "mssql"),
    (r"internet information services", "iis"),
    (r"world wide web publishing", "iis"),
    (r"\biis\b", "iis"),
    (r"microsoft exchange", "msexch"),
    (r"msexchange", "msexch"),
    (r"\bexchange\b", "msexch"),
    (r"postgresql", "postgres"),
    (r"mariadb", "mysql"),
    (r"\bmysql\b", "mysql"),
    (r"apache tomcat", "jolokia"),
    (r"\btomcat\b", "jolokia"),
    (r"apache http", "apache"),
    (r"\bnginx\b", "nginx"),
    (r"\bredis\b", "redis"),
    (r"mongo", "mongodb"),
    (r"\bdocker\b", "docker"),
    (r"\blibrabbitmq\d*\b", "librabbitmqclient"),
    (r"rabbitmq-server", "rabbitmq"),
    (r"rabbitmq", "rabbitmq"),
    (r"elasticsearch", "elasticsearch"),
    (r"\bhaproxy\b", "haproxy"),
    (r"\bpostfix\b", "postfix"),
    (r"\bnfs-kernel-server\b", "nfsexports"),
    (r"\bnfs-server\b", "nfsexports"),
    (r"\bisc-dhcp-client\b", "iscdhcpclient"),
    (r"\bisc-dhcp-common\b", "iscdhcpcommon"),
    (r"\bisc-dhcp-server\b", "isc"),
    (r"\bceph-common\b", "cephclient"),
    (r"\bceph-fuse\b", "cephclient"),
    (r"oracle database", "oracle"),
    (r"\boracle\b", "oracle"),
    # Windows "DHCP Server" role service (service name "DHCPServer",
    # display name "DHCP Server") - distinct from the Linux
    # isc-dhcp-server signature above, which maps to the unrelated "isc"
    # token/plug-in.
    (r"\bdhcp server\b", "windhcp"),
    (r"\bdhcpserver\b", "windhcp"),
)
SIGNATURES: tuple[tuple[Any, str], ...] = tuple(
    (re.compile(pat, re.IGNORECASE), tok) for pat, tok in _SIGNATURES_RAW
)

# Checkmk plug-in name -> canonical token, for plug-ins whose name's leading
# alnum run (as extracted by _plugin_token()'s generic tokenizer) is too
# generic/ambiguous to use directly, e.g. "win_dhcp_pools" would otherwise
# tokenize to the bare "win" (colliding with any other "win_*" plug-in).
PLUGIN_TOKEN_OVERRIDES: dict[str, str] = {
    "win_dhcp_pools": "windhcp",
}

# systemd units that are part of a package's standard boot-time housekeeping
# and settle into "loaded active" on virtually every install of that package,
# regardless of whether the feature is actually used (no matching
# ConditionPathExists=/ConditionDirectoryNotEmpty=/... to gate them). Unlike
# e.g. zfs-import-scan.service (skipped/inactive without an importable pool),
# these carry no signal that the subsystem is in active use, so they must not
# be treated as evidence of a running capability.
# NOTE: names here are WITHOUT the unit-type suffix (.service/.socket/...),
# matching how cmk.plugins.collection.agent_based.systemd_units.UnitEntry.name
# is parsed (suffix is split off separately as the unit type).
SYSTEMD_ALWAYS_ON_UNITS: frozenset[str] = frozenset({
    # LVM2's dmeventd/activation/polling hooks ship - and are enabled - with
    # the base "lvm2" package on Debian/Ubuntu and run at every boot even on
    # hosts with no volume group at all.
    "lvm2-monitor",
    "lvm2-lvmpolld",
    "lvm2-activation-early",
    "lvm2-activation",
    "lvm2-activation-net",
})

# Prefix families that behave the same way as SYSTEMD_ALWAYS_ON_UNITS above,
# but have too many differently-named instances to enumerate individually
# (e.g. distro/version-specific "lvm2-*" boot hooks). Matched with
# str.startswith() against the unit name (without type suffix).
SYSTEMD_ALWAYS_ON_PREFIXES: tuple[str, ...] = (
    "lvm2-",
)


def _is_always_on_unit(name: str) -> bool:
    if name in SYSTEMD_ALWAYS_ON_UNITS:
        return True
    return any(name.startswith(p) for p in SYSTEMD_ALWAYS_ON_PREFIXES)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _join(string_table: StringTable) -> str:
    return "".join(part for row in string_table for part in row)


def _parse_json(string_table: StringTable) -> Mapping[str, Any] | None:
    raw = _join(string_table)
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


agent_section_monitoring_compliance_serverinfo = AgentSection(
    name="monitoring_compliance_serverinfo",
    parse_function=_parse_json,
)

agent_section_monitoring_compliance_inventory = AgentSection(
    name="monitoring_compliance_inventory",
    parse_function=_parse_json,
)


# ---------------------------------------------------------------------------
# Defensive extraction from standard (built-in) sections
# ---------------------------------------------------------------------------

def _basename(value: str) -> str:
    return os.path.basename(value.strip().strip("[]"))


def _as_str_list(value: Any) -> list[str]:
    """Coerce a JSON value into a list of strings (handles scalars)."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _running_from_ps(section_ps: Any) -> set[str]:
    names: set[str] = set()
    if not section_ps:
        return names
    entries: Any = section_ps
    if (isinstance(section_ps, tuple) and len(section_ps) == 2
            and not isinstance(section_ps[1], str)):
        entries = section_ps[1]
    try:
        iterator = iter(entries)
    except TypeError:
        return names
    for entry in iterator:
        try:
            cmd_tokens: Sequence[str] | None = None
            if isinstance(entry, (tuple, list)) and len(entry) >= 2 \
                    and isinstance(entry[1], (list, tuple)):
                cmd_tokens = [str(t) for t in entry[1]]
            else:
                cmd = getattr(entry, "command_line", None)
                if cmd is None and isinstance(entry, (list, tuple)) and entry:
                    cmd = entry[-1]
                if isinstance(cmd, (list, tuple)):
                    cmd_tokens = [str(t) for t in cmd]
                elif isinstance(cmd, str):
                    cmd_tokens = cmd.split()
            if not cmd_tokens:
                continue
            names.add(_basename(cmd_tokens[0]))
        except Exception:  # noqa: BLE001
            continue
    return names


def _running_from_services(section_services: Any) -> set[str]:
    """Running-service evidence from Checkmk's built-in Windows "services"
    section (WinService(name, state, start_type, description) tuples,
    already parsed by cmk's own agent_section_services parser).

    Only entries whose current state is "running" count as real
    running-evidence (mirrors _systemd_units()'s ACTIVE=active check) -
    a service merely being installed/stopped must not count. Both the
    short service name (e.g. "MSSQL$ELOECHT") and the human-readable
    description (e.g. "SQL Server (ELOECHT)") are added so tokenisation
    can match either form against a plug-in name.
    """
    names: set[str] = set()
    if not section_services:
        return names
    try:
        iterator = iter(section_services)
    except TypeError:
        return names
    for entry in iterator:
        try:
            name = getattr(entry, "name", None)
            state = getattr(entry, "state", None)
            description = getattr(entry, "description", None)
            if name is None and isinstance(entry, (list, tuple)) and len(entry) >= 2:
                name, state = entry[0], entry[1]
                description = entry[3] if len(entry) >= 4 else None
            if not name or state != "running":
                continue
            names.add(str(name))
            if description:
                names.add(str(description))
        except Exception:  # noqa: BLE001
            continue
    return names


def _names_from_section(section: Any, keys: Sequence[str]) -> set[str]:
    names: set[str] = set()
    if not section:
        return names
    try:
        iterator = iter(section)
    except TypeError:
        return names
    for entry in iterator:
        try:
            if isinstance(entry, Mapping):
                for k in keys:
                    if entry.get(k):
                        names.add(str(entry[k]))
                        break
            elif isinstance(entry, (list, tuple)) and entry:
                names.add(str(entry[0]))
            else:
                for k in keys:
                    val = getattr(entry, k, None)
                    if val:
                        names.add(str(val))
                        break
        except Exception:  # noqa: BLE001
            continue
    return names


def _systemd_units(section: Any) -> set[str]:
    """Unit names from the built-in systemd_units section that are actually
    present and active right now.

    The raw section lists every unit systemd knows about, which includes a
    lot of noise that must NOT be treated as "this application is running":

      - "not-found" units (LOAD=not-found): pure ghost references pulled in
        via another unit's Wants=/After=, the software itself was never
        installed (e.g. a stray "postfix.service" on a host without mail
        server, or "nfs-server.service" without NFS installed).
      - "masked" units (LOAD=masked): explicitly disabled, cannot run.
      - Template units without an instance (name ends in "@", e.g.
        "openvpn@.service", "zfs-mount@.service"): these can never be
        active themselves, only concrete instances like "openvpn@foo" can.

    LOAD=loaded + ACTIVE=active is the correct signal regardless of the
    low-level SUB state: boot-time oneshot units for real, in-use software
    correctly settle into "active exited" (e.g. zfs-mount.service,
    zfs-share.service on a host with an imported zpool) just like
    long-running daemons show "active running" (e.g. zfs-zed.service).
    ENABLED status (enabled/disabled/static/generated) says nothing about
    whether the unit is currently in use and is intentionally ignored here.
    """
    names: set[str] = set()
    if not section:
        return names
    # try common shapes: object with .services / dict / iterable of objects
    candidates: Any = section
    for attr in ("services", "units"):
        sub = getattr(section, attr, None)
        if sub is not None:
            candidates = sub
            break
    if isinstance(candidates, Mapping):
        iterable = candidates.values()
    else:
        iterable = candidates
    try:
        iterator = iter(iterable)
    except TypeError:
        return names
    for entry in iterator:
        try:
            name = (getattr(entry, "name", None)
                    or (entry.get("name") if isinstance(entry, Mapping) else None))
            if not name:
                continue
            name = str(name)
            # Template unit without an instance (e.g. "openvpn@") can never
            # be active by itself - only a concrete instance could be.
            if name.endswith("@"):
                continue
            loaded_status = (getattr(entry, "loaded_status", None)
                              or (entry.get("loaded_status") if isinstance(entry, Mapping) else None))
            active_status = (getattr(entry, "active_status", None)
                              or (entry.get("active_status") if isinstance(entry, Mapping) else None))
            # If we can't read the state at all, fall back to the old
            # name-only behaviour rather than silently dropping everything
            # (keeps this robust against unexpected section shapes).
            if loaded_status is None and active_status is None:
                if not _is_always_on_unit(name):
                    names.add(name)
                continue
            if str(loaded_status) != "loaded":
                continue
            if str(active_status) != "active":
                continue
            if _is_always_on_unit(name):
                continue
            names.add(name)
        except Exception:  # noqa: BLE001
            continue
    return names


# ---------------------------------------------------------------------------
# Capability collection
# ---------------------------------------------------------------------------

def _usage_evidence(
    section_df: Any,
    section_zfsget: Any = None,
    section_systemd_units: Any = None,
    section_md: Any = None,
    section_services: Any = None,
) -> frozenset[str]:
    """Derive real-usage evidence for kernel/storage features from
    already-collected agent sections - no extra agent plug-in required.

    - "zfs":  any mounted filesystem has fs_type == "zfs" in the "df" section,
              OR the "zfsget" section (checkmk's own zfs list parser) has at
              least one parsed dataset. The df route alone is not reliable
              here: on some hosts (observed on Proxmox VE with a ZFS root
              pool) the agent's df output omits ZFS-backed mounts entirely,
              even though ZFS is actively used - zfsget is the direct,
              ZFS-native usage signal for that case.
    - "lvm":  any mounted filesystem's device is an LVM-managed block device,
              i.e. /dev/mapper/<vg>-<lv> or /dev/dm-<N> (the device naming
              the kernel itself uses for active LVM logical volumes).
    - "corosync": the corosync.service systemd unit is actually loaded+active
              right now (see _systemd_units()). The corosync *package* alone
              is not evidence of cluster usage - on Proxmox VE it is a
              standard dependency pulled in on every install, clustered or
              not, so the package being present says nothing about whether
              this host is part of a cluster.
    - "dmraid": the "md" section (kernel /proc/mdstat, parsed by checkmk's
              built-in "md" agent section) reports at least one actual
              array. The dmraid *package* alone is not evidence of an
              active software RAID - on openSUSE it ships pre-installed
              on virtually every install regardless of whether any disk
              set is actually configured as a RAID.
    - "mssql": the built-in Windows "services" section (WinService entries)
              contains a service whose name/description matches
              MSSQL.*running (i.e. a "MSSQL$<instance>"/"MSSQLSERVER" service
              that is actually running right now). This is deliberately
              stricter than the other tokens above (which accept mere
              presence of a feature): only a *running* SQL Server engine
              service is accepted as corroboration, so package-only hits
              (SQL Server Compact, ODBC/OLE DB drivers, SSMS, ...) can never
              trigger the "Deploy mssql.vbs" recommendation, matching what a
              human checking "is SQL Server actually running here?" would
              look for first.
    - "iis":  the built-in Windows "services" section contains the actual
              web-serving engine service ("W3SVC" / "World Wide Web
              Publishing Service") in a running state. Deliberately NOT
              satisfied by other IIS-branded management/admin services such
              as "IIS-Verwaltungsdienst" (WMSVC, the remote IIS Manager
              service) - that service can be running/installed while the
              web-serving engine itself is stopped or not installed at all,
              which would otherwise wrongly suggest deploying the IIS
              application-pool plug-in on a host that never actually serves
              anything via IIS.
    """
    evidence: set[str] = set()
    if section_df:
        blocks: Any = section_df
        # cmk.plugins.lib.df.DfSection is (BlocksSubsection, InodesSubsection);
        # be defensive about other/older shapes too.
        if isinstance(section_df, tuple) and len(section_df) == 2:
            blocks = section_df[0]
        try:
            iterator = iter(blocks)
        except TypeError:
            iterator = iter(())
        for entry in iterator:
            try:
                device = str(getattr(entry, "device", None)
                            or (entry.get("device") if isinstance(entry, Mapping) else "") or "")
                fs_type = str(getattr(entry, "fs_type", None)
                             or (entry.get("fs_type") if isinstance(entry, Mapping) else "") or "")
            except Exception:  # noqa: BLE001
                continue
            if fs_type.lower() == "zfs":
                evidence.add("zfs")
            if device.startswith("/dev/mapper/") or re.match(r"^/dev/dm-\d+$", device):
                evidence.add("lvm")

    if section_zfsget:
        # section_zfsget is the *parsed* "zfsget" AgentSection, a mapping of
        # mountpoint -> FSBlock (mountpoint, size_mb, avail_mb, reserved).
        # Any entry at all means the agent found real ZFS datasets - the
        # zfsget plug-in's own parser already collapsed name/type/mountpoint
        # into this mapping, so simply being present is the usage signal.
        try:
            if len(section_zfsget) > 0:
                evidence.add("zfs")
        except TypeError:
            pass

    if "corosync.service" in _systemd_units(section_systemd_units):
        evidence.add("corosync")

    if section_md:
        try:
            has_rows = any(True for _ in iter(section_md))
        except TypeError:
            has_rows = bool(section_md)
        if has_rows:
            evidence.add("dmraid")

    if section_services:
        mssql_running = re.compile(r"mssql", re.IGNORECASE)
        iis_running = re.compile(r"^w3svc$|world wide web publishing", re.IGNORECASE)
        try:
            iterator = iter(section_services)
        except TypeError:
            iterator = iter(())
        for entry in iterator:
            try:
                svc_name = str(getattr(entry, "name", None)
                               or (entry.get("name") if isinstance(entry, Mapping) else "") or "")
                svc_desc = str(getattr(entry, "description", None)
                               or (entry.get("description") if isinstance(entry, Mapping) else "") or "")
                svc_state = str(getattr(entry, "state", None)
                                or (entry.get("state") if isinstance(entry, Mapping) else "") or "")
            except Exception:  # noqa: BLE001
                continue
            if svc_state.lower() != "running":
                continue
            if mssql_running.search(svc_name) or mssql_running.search(svc_desc):
                evidence.add("mssql")
            if iis_running.search(svc_name) or iis_running.search(svc_desc):
                evidence.add("iis")

    return frozenset(evidence)


def _collect_capabilities(
    serverinfo: Mapping[str, Any],
    inv: Mapping[str, Any] | None,
    present_sections: Sequence[str],
    section_ps: Any,
    section_systemd_units: Any,
    section_services: Any = None,
) -> set[tuple[str, str]]:
    caps: set[tuple[str, str]] = set()

    # 1) existing agent sections
    for sec in present_sections:
        caps.add((T_SECTION, sec))

    # 2) systemd units / services / processes / packages from the agent plug-in
    if inv:
        for u in _as_str_list(inv.get("systemd_units")):
            caps.add((T_SYSTEMD, u))
        for u in _as_str_list(inv.get("services")):
            caps.add((T_SERVICE, u))
        for p in _as_str_list(inv.get("processes")):
            caps.add((T_PROCESS, _basename(p)))
        for p in _as_str_list(inv.get("packages")):
            caps.add((T_PACKAGE, p))
    for u in _systemd_units(section_systemd_units):
        caps.add((T_SYSTEMD, u))

    # 2b) built-in Windows "services" section (running Windows services,
    # no custom agent plug-in required - see _running_from_services())
    for u in _running_from_services(section_services):
        caps.add((T_SERVICE, u))

    # 3) processes from ps
    for p in _running_from_ps(section_ps):
        caps.add((T_PROCESS, p))

    # 4) host labels (server side)
    for k, v in (serverinfo.get("host_labels", {}) or {}).items():
        caps.add((T_LABEL, f"{k}:{v}"))

    # 5) HW/SW inventory packages (server side)
    for p in serverinfo.get("inventory_packages", []) or []:
        caps.add((T_INV_PACKAGE, str(p)))

    return caps


# ---------------------------------------------------------------------------
# Token correlation
# ---------------------------------------------------------------------------

def _strip_suffix(s: str) -> str:
    for suf in (".service", ".socket", ".timer", ".exe", ".target"):
        if s.endswith(suf):
            return s[: -len(suf)]
    return s


def _resolve_token(raw: str, custom_rules: Sequence[Mapping[str, Any]]) -> str:
    # 1) user-defined rules
    for rule in custom_rules:
        try:
            if re.search(rule["pattern"], raw, re.IGNORECASE):
                return str(rule["token"]).lower()
        except (re.error, KeyError):
            continue
    # 2) built-in signatures (handles verbose / Windows display names)
    for rx, tok in SIGNATURES:
        if rx.search(raw):
            return tok
    # 3) generic leading-token extraction
    s = _basename(raw).lower()
    s = _strip_suffix(s)
    if ":" in s:  # host label "key:value" -> value
        s = s.split(":", 1)[1]
    m = re.match(r"[a-z][a-z0-9+]*", s)
    base = re.sub(r"\d+$", "", m.group(0)) if m else ""
    if base in ALIASES:
        return ALIASES[base]
    # 4) CamelCase fallback, only for separator-free names such as
    #    "MSExchangeTransport" (avoids matching embedded words in compound
    #    names like "prometheus-apache-exporter").
    bn = _strip_suffix(_basename(raw))
    if not re.search(r"[\s_\-]", bn):
        for part in re.findall(r"[A-Z][a-z0-9]+", bn):
            pl = part.lower()
            if pl in ALIASES:
                return ALIASES[pl]
    return base


def _plugin_token(name: str) -> str:
    n = name.lower()
    override = PLUGIN_TOKEN_OVERRIDES.get(n)
    if override:
        return override
    m = re.match(r"[a-z0-9]+", n)
    return m.group(0) if m else ""


def _token_index(plugins: Sequence[str]) -> dict[str, set[str]]:
    idx: dict[str, set[str]] = {}
    for p in plugins:
        tok = _plugin_token(str(p))
        if tok:
            idx.setdefault(tok, set()).add(str(p))
    return idx


# ---------------------------------------------------------------------------
# Capability database (persistent, deduplicated, grows over time)
# ---------------------------------------------------------------------------

_DB_MIN_WRITE_INTERVAL = 1800  # seconds
_DB_MAX_ENTRIES = 50000
_DB_MAX_HOSTS_PER_ENTRY = 50


def _db_path(params: Mapping[str, Any]) -> str | None:
    custom = params.get("capability_db_path")
    if custom:
        return str(custom)
    omd_root = os.environ.get("OMD_ROOT")
    if not omd_root:
        return None
    return os.path.join(omd_root, "var", "monitoring_compliance",
                        "capability_db.json")


def _update_capability_db(
    path: str,
    host: str,
    caps_meta: Sequence[tuple[str, str, str, bool, bool]],
) -> dict[str, int]:
    """Merge capabilities into the DB. Returns simple stats. Best effort."""
    stats: dict[str, int] = {}
    try:
        import fcntl  # noqa: PLC0415
        import tempfile  # noqa: PLC0415

        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        lock_path = path + ".lock"
        with open(lock_path, "w", encoding="utf-8") as lock_fh:
            fcntl.flock(lock_fh, fcntl.LOCK_EX)
            db: dict[str, Any] = {"capabilities": {}, "updated_ts": 0}
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict) and "capabilities" in loaded:
                    db = loaded
            except Exception:  # noqa: BLE001
                pass

            entries: dict[str, Any] = db.get("capabilities", {})
            now = int(time.time())
            new_keys = 0
            for ctype, name, token, monitorable, monitored in caps_meta:
                key = f"{ctype}\u0000{name}"
                rec = entries.get(key)
                if rec is None:
                    if len(entries) >= _DB_MAX_ENTRIES:
                        continue
                    entries[key] = {
                        "type": ctype, "name": name, "token": token,
                        "first_seen": now, "last_seen": now,
                        "hosts": [host],
                        "monitorable": bool(monitorable),
                        "monitored": bool(monitored),
                    }
                    new_keys += 1
                else:
                    rec["last_seen"] = now
                    rec["token"] = token or rec.get("token", "")
                    rec["monitorable"] = bool(rec.get("monitorable")) or monitorable
                    rec["monitored"] = bool(rec.get("monitored")) or monitored
                    hosts = rec.setdefault("hosts", [])
                    if host not in hosts and len(hosts) < _DB_MAX_HOSTS_PER_ENTRY:
                        hosts.append(host)

            db["capabilities"] = entries
            stats = {
                "total": len(entries),
                "new": new_keys,
            }

            stale = (now - int(db.get("updated_ts", 0))) > _DB_MIN_WRITE_INTERVAL
            if new_keys or stale:
                db["updated_ts"] = now
                fd, tmp = tempfile.mkstemp(dir=directory)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(db, fh)
                os.replace(tmp, path)
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
    except Exception:  # noqa: BLE001
        return stats
    return stats


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def _compile(patterns: Sequence[str]) -> list[Any]:
    out: list[Any] = []
    for pat in patterns:
        try:
            out.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            out.append(pat)
    return out


def _is_ignored(value: str, compiled: Sequence[Any]) -> bool:
    for c in compiled:
        if isinstance(c, str):
            if c.lower() in value.lower():
                return True
        elif c.search(value):
            return True
    return False


# ---------------------------------------------------------------------------
# Discovery & check
# ---------------------------------------------------------------------------

def discover_monitoring_compliance(
    section_monitoring_compliance_serverinfo,
    section_monitoring_compliance_inventory,
    section_ps,
    section_systemd_units,
    section_services,
    section_df,
    section_zfsget,
    section_md,
) -> DiscoveryResult:
    if section_monitoring_compliance_serverinfo is not None:
        yield Service()


def check_monitoring_compliance(
    params: Mapping[str, Any],
    section_monitoring_compliance_serverinfo,
    section_monitoring_compliance_inventory,
    section_ps,
    section_systemd_units,
    section_services,
    section_df,
    section_zfsget,
    section_md,
) -> CheckResult:
    info = section_monitoring_compliance_serverinfo
    if info is None:
        yield Result(
            state=State.UNKNOWN,
            summary="No server-side compliance data. Enable the 'Checkmk "
                    "Monitoring Compliance' (special agent) rule for this host.",
        )
        return

    host = str(info.get("host", ""))
    available = [str(p) for p in info.get("available_plugins", []) or []]
    monitored = [str(p) for p in info.get("monitored_plugins", []) or []]
    skip_avail = bool(info.get("availability_skipped"))
    errors = list(info.get("errors", []) or [])

    avail_idx = _token_index(available)
    mon_idx = _token_index(monitored)

    # which consumed sections are present on this host
    present_sections: list[str] = []
    for nm, sec in (
        ("ps", section_ps),
        ("systemd_units", section_systemd_units),
        ("services", section_services),
        ("monitoring_compliance_inventory", section_monitoring_compliance_inventory),
    ):
        if sec:
            present_sections.append(nm)

    caps = _collect_capabilities(
        info, section_monitoring_compliance_inventory, present_sections,
        section_ps, section_systemd_units, section_services,
    )

    ign_proc = _compile(params.get("ignored_processes", []) or [])
    ign_prog = _compile(params.get("ignored_programs", []) or [])
    custom_rules = list(params.get("custom_catalog", []) or [])

    usage_evidence = _usage_evidence(
        section_df, section_zfsget, section_systemd_units, section_md, section_services,
    )

    state_running = State(int(params.get("state_running_unmonitored", 2)))
    state_installed = State(int(params.get("state_installed_unmonitored", 1)))
    info_only = bool(params.get("informational_only"))

    # group capabilities into applications by canonical token
    apps: dict[str, dict[str, Any]] = {}
    by_type: dict[str, int] = {}
    caps_meta: list[tuple[str, str, str, bool, bool]] = []

    for ctype, name in caps:
        by_type[ctype] = by_type.get(ctype, 0) + 1

        # Ignore filters: "ignore processes" applies to running-type
        # capabilities (processes, systemd units, Windows services); "ignore
        # installed programs" applies to packages. Host labels are matched by
        # either list.
        ignored = False
        if ctype in RUNNING_TYPES and _is_ignored(name, ign_proc):
            ignored = True
        elif ctype in INSTALLED_TYPES and _is_ignored(name, ign_prog):
            ignored = True
        elif ctype == T_LABEL and (_is_ignored(name, ign_proc)
                                   or _is_ignored(name, ign_prog)):
            ignored = True
        if ignored:
            continue

        token = _resolve_token(name, custom_rules)
        monitorable = bool(avail_idx.get(token)) if not skip_avail else bool(token)
        is_mon = bool(mon_idx.get(token))
        caps_meta.append((ctype, name, token, monitorable, is_mon))

        if not token or token in STOP_TOKENS:
            continue
        if not monitorable:
            continue
        # Client-only packages/units/processes (e.g. "mysql-common",
        # "nut-client"/"nut-monitor") must not count as evidence that the
        # corresponding server is installed or running.
        excl = EVIDENCE_EXCLUDE.get(token)
        if excl and excl.search(name):
            continue
        # Kernel/library features (LVM, ZFS, ...): package/inventory presence
        # alone proves nothing was ever actually used. Require corroborating
        # evidence from the df section; drop the capability entirely if that
        # evidence is missing, regardless of which source found it.
        if token in TOKENS_REQUIRE_USAGE_EVIDENCE and token not in usage_evidence:
            continue
        # For the same tokens, an installed *package* (T_PACKAGE/
        # T_INV_PACKAGE) can never itself be the required usage evidence -
        # only a running-type source (process/systemd unit/Windows
        # service) can. So once a token has cleared the check above (real
        # usage evidence exists from a running-type source elsewhere),
        # installed packages must still be excluded from "sources": showing
        # e.g. an unrelated client driver/tool/demo-app package next to the
        # real running-service evidence in "[detected via ...]" is
        # confusing and provides no useful information about what to
        # monitor. This is generic by capability type, not a per-token
        # name-pattern list that would need constant upkeep.
        if token in TOKENS_REQUIRE_USAGE_EVIDENCE and ctype in INSTALLED_TYPES:
            continue

        app = apps.setdefault(token, {
            "installed": False, "running": False, "types": set(),
            "sources": set(),
        })
        app["types"].add(ctype)
        app["sources"].add((ctype, name))
        if ctype in RUNNING_TYPES:
            app["running"] = True
        if ctype in INSTALLED_TYPES or ctype == T_LABEL:
            app["installed"] = True

    # evaluate each application
    monitored_items: list[tuple[str, str]] = []
    findings: list[tuple[State, str]] = []
    monitored_count = 0

    for token, app in apps.items():
        title = TITLES.get(token, token.replace("_", " ").title())
        covering = sorted(mon_idx.get(token, set()))
        if covering:
            monitored_count += 1
            monitored_items.append((title, ", ".join(covering)))
            continue

        running = app["running"]
        if running:
            st = State.OK if info_only else state_running
            msg = f"{title}: running, not monitored"
        else:
            st = State.OK if info_only else state_installed
            msg = f"{title}: present, not running, not monitored"
        cands = sorted(avail_idx.get(token, set()))
        hint = HINTS.get(token)
        if hint:
            msg += f" \u2013 {hint}"
        elif cands:
            msg += f" \u2013 available plug-in(s): {', '.join(cands[:3])}"

        # show where it was detected, to make ignore configuration easy
        srcs = sorted(app.get("sources", set()))
        if srcs:
            shown = "; ".join(f"{ct}='{nm}'" for ct, nm in srcs[:4])
            if len(srcs) > 4:
                shown += f"; +{len(srcs) - 4} more"
            msg += f" [detected via {shown}]"
        findings.append((st, msg))

    total = len(apps)
    percent = 100.0 if total == 0 else round(100.0 * monitored_count / total, 1)
    open_count = total - monitored_count

    if total == 0:
        headline = "Compliance: 100% \u2013 no monitorable subsystems detected"
    else:
        headline = (f"Compliance: {percent:.0f}% \u2013 {monitored_count}/"
                    f"{total} monitorable subsystems monitored")
        if open_count:
            headline += f", {open_count} open"

    yield Result(state=State.OK, summary=headline)
    yield Metric("compliance_percent", percent, boundaries=(0.0, 100.0))

    # update the persistent capability database (best effort, never fatal)
    db_stats: dict[str, int] = {}
    if not params.get("disable_capability_db") and host:
        path = _db_path(params)
        if path:
            db_stats = _update_capability_db(path, host, caps_meta)

    # long output: monitored subsystems (OK, details only) ...
    for title, plugins in sorted(monitored_items):
        yield Result(state=State.OK,
                     notice=f"{title}: monitored (via {plugins})")

    # ... then the unmonitored findings (CRIT first, then WARN) ...
    for st, msg in sorted(findings, key=lambda f: -int(f[0])):
        yield Result(state=st, notice=msg)

    # ... then a capability/source summary line
    src = ", ".join(f"{t}:{n}" for t, n in sorted(by_type.items()))
    summary_line = f"Capabilities detected: {len(caps)}"
    if src:
        summary_line += f" ({src})"
    if db_stats.get("total") is not None:
        summary_line += (f"; capability DB: {db_stats['total']} entries"
                         f", {db_stats.get('new', 0)} new")
    yield Result(state=State.OK, notice=summary_line)

    if errors:
        yield Result(state=State.OK,
                     notice="Notes from the special agent: " + "; ".join(errors))


check_plugin_monitoring_compliance = CheckPlugin(
    name="monitoring_compliance",
    sections=[
        "monitoring_compliance_serverinfo",
        "monitoring_compliance_inventory",
        "ps",
        "systemd_units",
        "services",
        "df",
        "zfsget",
        "md",
    ],
    service_name="Checkmk Monitoring Compliance",
    discovery_function=discover_monitoring_compliance,
    check_function=check_monitoring_compliance,
    check_ruleset_name="monitoring_compliance",
    check_default_parameters={
        "state_running_unmonitored": 2,
        "state_installed_unmonitored": 1,
        "informational_only": False,
        "ignored_processes": [],
        "ignored_programs": [],
        "custom_catalog": [],
        "disable_capability_db": False,
    },
)
