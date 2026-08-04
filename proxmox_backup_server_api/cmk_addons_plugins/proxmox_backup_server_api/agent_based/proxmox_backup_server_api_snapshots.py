#!/usr/bin/env python3
"""PBS backup-age check — freshness of the newest backup per group.

Consumes the ``proxmox_backup_server_api_snapshots`` section emitted by the
special agent. The agent already reduced every snapshot to the newest
``backup-time`` per backup group (type/id), per datastore and namespace, so
this check only has to turn those timestamps into an age and compare against
the configured warn/crit thresholds.

One service is discovered per datastore and one per datastore+namespace
(``"<store>, Namespace: <ns>"``), mirroring the legacy ``pbs_snapshot_age``
plugin so existing rules keep working.
"""
import fnmatch
import json
import re
import time
from typing import Any, Mapping

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    RuleSetType,
    Service,
    State,
    StringTable,
    render,
)

Section = dict


def parse_proxmox_backup_server_api_snapshots(string_table: StringTable) -> Section:
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_proxmox_backup_server_api_snapshots = AgentSection(
    name="proxmox_backup_server_api_snapshots",
    parse_function=parse_proxmox_backup_server_api_snapshots,
)


def _iter_items(section: Section):
    """Yield every discoverable item: each datastore and each store+namespace."""
    for store, store_entry in section.items():
        yield store
        if isinstance(store_entry, dict) and "_error" not in store_entry:
            for ns in store_entry:
                yield "%s, Namespace: %s" % (store, ns)


def discover_proxmox_backup_server_api_snapshots(
    params: Mapping[str, Any], section: Section
) -> DiscoveryResult:
    selector = params.get("datastores", ("all", "all"))
    mode = selector[0]
    if mode == "selected":
        wanted = selector[1].split("\n")
        for item in _iter_items(section):
            store = item.split(", Namespace: ")[0]
            if store in wanted:
                yield Service(item=item)
    elif mode == "regex":
        rx = re.compile(selector[1])
        for item in _iter_items(section):
            store = item.split(", Namespace: ")[0]
            if rx.match(store):
                yield Service(item=item)
    else:
        for item in _iter_items(section):
            yield Service(item=item)


def _collect_groups(item: str, section: Section):
    """Return (groups_dict, error_or_None) for the requested item.

    groups_dict maps "type/id" -> {latest, verify, count}. For a bare
    datastore item all namespaces are merged (keeping the freshest entry per
    group key).
    """
    split = item.split(", Namespace: ")
    store = split[0]
    store_entry = section.get(store)
    if store_entry is None:
        return None, "Datastore not found in API output"
    if isinstance(store_entry, dict) and "_error" in store_entry:
        return None, store_entry["_error"]

    if len(split) == 2:
        ns_entry = store_entry.get(split[1])
        if ns_entry is None:
            return None, "Namespace not found in API output"
        if isinstance(ns_entry, dict) and "_error" in ns_entry:
            return None, ns_entry["_error"]
        return dict(ns_entry), None

    # Bare datastore: merge all namespaces, freshest wins per group key.
    merged: dict = {}
    for ns_entry in store_entry.values():
        if not isinstance(ns_entry, dict) or "_error" in ns_entry:
            continue
        for gkey, g in ns_entry.items():
            cur = merged.get(gkey)
            if cur is None or g.get("latest", 0) > cur.get("latest", 0):
                merged[gkey] = g
    return merged, None


def check_proxmox_backup_server_api_snapshots(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    groups, err = _collect_groups(item, section)
    if err is not None:
        yield Result(state=State.UNKNOWN, summary=err)
        return

    # Drop groups the user asked to ignore (exact key or shell-style wildcard,
    # e.g. "vm/9000", "vm/*", "*/9000"). Ignored groups are neither counted
    # nor listed in the details.
    ignore_patterns = params.get("ignore_groups") or []
    num_ignored = 0
    if ignore_patterns:
        kept = {}
        for gkey, g in groups.items():
            if any(fnmatch.fnmatch(gkey, pat) for pat in ignore_patterns):
                num_ignored += 1
                continue
            kept[gkey] = g
        groups = kept

    err_days = params.get("err_days")
    warn = crit = None
    if err_days is not None:
        warn, crit = err_days[1]
    ignore_old = params.get("ignore_old_errors")
    throw = params.get("throw_warnings", True)

    now = time.time()
    num_warn = num_crit = 0
    crit_groups = []
    warn_groups = []
    oldest_age = None
    details_lines = []

    for gkey in sorted(groups):
        g = groups[gkey]
        latest = g.get("latest")
        if latest is None:
            continue
        age = now - float(latest)
        if oldest_age is None or age > oldest_age:
            oldest_age = age

        level = "OK"
        if err_days is not None:
            if age > crit:
                level = "CRIT"
            elif age > warn:
                level = "WARN"

        # ignore_old_errors: suppress alerts for backups so stale they are
        # considered abandoned rather than actively failing.
        counts = ignore_old is None or age < ignore_old
        suppressed = not counts and level in ("WARN", "CRIT")
        if level == "CRIT" and counts:
            num_crit += 1
            crit_groups.append("%s (%s)" % (gkey, render.timespan(age)))
        elif level == "WARN" and counts:
            num_warn += 1
            warn_groups.append("%s (%s)" % (gkey, render.timespan(age)))

        details_lines.append(
            "State: %s   Group: %s   last backup: %s ago (%s)%s"
            % (level, gkey, render.timespan(age),
               render.datetime(float(latest)),
               "   (ignored by rule)" if suppressed else "")
        )

    total = len(groups)
    ignored_note = (
        " (%d ignored)" % num_ignored if num_ignored else ""
    )

    if num_crit > 0:
        crit_days = int(crit / 86400.0) if crit else 0
        yield Result(
            state=State.CRIT if throw else State.OK,
            summary="%d backup%s older than %d day%s: %s"
            % (num_crit, "s" if num_crit != 1 else "",
               crit_days, "s" if crit_days != 1 else "",
               ", ".join(crit_groups)),
        )
    if num_warn > 0:
        warn_days = int(warn / 86400.0) if warn else 0
        yield Result(
            state=State.WARN if throw else State.OK,
            summary="%d backup%s older than %d day%s: %s"
            % (num_warn, "s" if num_warn != 1 else "",
               warn_days, "s" if warn_days != 1 else "",
               ", ".join(warn_groups)),
        )
    if num_crit == 0 and num_warn == 0:
        yield Result(state=State.OK, summary="No stale backups")

    yield Result(
        state=State.OK,
        summary="%d backup group%s%s" % (total, "s" if total != 1 else "", ignored_note),
        details="\n".join(details_lines) if details_lines else None,
    )

    if oldest_age is not None:
        levels = (warn, crit) if err_days is not None else None
        yield Metric("backup_age", oldest_age, levels=levels)


check_plugin_proxmox_backup_server_api_snapshots = CheckPlugin(
    name="proxmox_backup_server_api_snapshots",
    service_name="PBS Backup Age %s",
    discovery_function=discover_proxmox_backup_server_api_snapshots,
    discovery_ruleset_name="proxmox_backup_server_api_snapshots_discovery",
    discovery_ruleset_type=RuleSetType.MERGED,
    discovery_default_parameters={"datastores": ("all", "all")},
    check_function=check_proxmox_backup_server_api_snapshots,
    check_ruleset_name="proxmox_backup_server_api_snapshots",
    check_default_parameters={
        "err_days": ("fixed", (2 * 86400.0, 10 * 86400.0)),
        "throw_warnings": True,
        "ignore_old_errors": None,
        "ignore_groups": [],
    },
)
