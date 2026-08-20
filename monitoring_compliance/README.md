# Checkmk Monitoring Compliance

Detects installed and/or running services on a host that are not yet monitored,
even though a suitable Checkmk plug-in is available on the server. The result
is a **"Checkmk Monitoring Compliance"** service with WARN/CRIT logic and a
compliance metric (`compliance_percent`).
<img width="1856" height="616" alt="image" src="https://github.com/user-attachments/assets/bbf15235-7a02-4bea-8a5d-c97b05307249" />


## How it works

Detection is capability-based rather than relying on a static application
list. Every data source contributes typed capabilities (type + name), which
are correlated to the check plug-ins available on the site via a normalized
name token and an alias table. Any program whose name matches an available
plug-in is therefore detected automatically.

Detection sources:

- Existing agent sections that are present on the host.
- Running systemd service units (agent plug-in or built-in section) and, on
  Windows, running services (via the Windows agent plug-in).
- Running processes (`ps` / `ps_lnx`).
- Host labels (read server-side via Livestatus).
- Installed packages from the HW/SW inventory (read server-side by the
  special agent) and from the optional agent plug-ins.

Capabilities are written to a persistent, deduplicated capability database.
The check does not bind the cached `lnx_packages` / `win_reg_uninstall` agent
sections, so the service is driven by live data and recomputes on the normal
check interval (and can be rescheduled). Installed-package data still only
changes as fast as the HW/SW inventory is refreshed.


## Services

| Service | Description |
|---|---|
| `Checkmk Monitoring Compliance` | Per-host compliance service (WARN/CRIT logic, `compliance_percent` metric) |
| `Checkmk Capability Database` | Statistics about the persistent capability database (file size, entry counts, distinct hosts/tokens, last update). Enable "Report capability database statistics" in the special-agent rule on exactly one host (e.g. the Checkmk server). |
| `Checkmk Known Catalog` | Read-only reference listing the application types the detection knows about (alias/signature/title tables), annotated with plug-in availability on this site. Always OK, informational only. Enable "Report known catalog" in the special-agent rule. |

## Deployment

- The special agent runs server-side and reads host labels, HW/SW inventory
  data and, when configured, the capability-database/known-catalog data.
- Optional agent plug-ins (`agents/plugins/mk_monitoring_compliance` for
  Linux/shell, `agents/windows/plugins/mk_monitoring_compliance.ps1` for
  Windows PowerShell) provide clean capability data straight from the host
  and can be deployed via the Agent Bakery (commercial editions).
- Configure the special agent via the ruleset "Checkmk Monitoring Compliance"
  (`monitoring_compliance/rulesets/special_agent.py`) and per-service
  thresholds via the corresponding check-parameter rulesets.

## Requirements

- Checkmk >= 2.3.0p1.
- Agent Bakery deployment of the optional plug-ins requires a commercial
  edition (CEE).

## Installing

```
mkp add monitoring_compliance-1.5.9.mkp
mkp enable monitoring_compliance 1.5.9
```

## Changelog

- **1.5.27** — Fixed two `BooleanChoice` fields in the "Checkmk Monitoring
  Compliance" special-agent rule and the check-parameter rule
  (`no_plugin_check`, `no_labels`, `no_inventory`, `report_db_stats`,
  `report_known_catalog` and `informational_only`,
  `disable_capability_db`) showing an unlabeled second checkbox stacked
  under the outer "enable this option" checkbox. Added an explicit
  `label=` to each affected `BooleanChoice`, so the inner checkbox now
  carries its own descriptive text instead of appearing blank.
- **1.5.26** — Fixed a false negative where PowerDNS (Authoritative
  Server + Recursor) was not detected as a capability even though it was
  installed and actively monitored. The package/process/systemd-unit
  names (`pdns`, `pdns-recursor`, `pdns_server`) were never mapped to the
  Checkmk plug-in prefix `powerdns_*` because no alias existed. Added the
  missing alias plus title/hint entries.
- **1.5.25** — Fixed a false positive where the Apache client-tools
  package (`apache2-utils`, and the equivalent `apache2-bin`/
  `httpd-tools` on other distros) was treated as evidence of an actual
  Apache HTTP server. These packages ship `htpasswd`/`ab`/`htdigest`
  only and are frequently pulled in as a dependency of unrelated
  packages. Now excluded via the client-only evidence exclusion.
- **1.5.24** — Fixed a false positive where the NUT (Network UPS Tools)
  client package (`nut-client`) and its `nut-monitor.service` unit
  (`upsmon` running in client mode) were treated as evidence of a local
  NUT server (`upsd`). The evidence-exclusion mechanism (previously
  `PACKAGE_EVIDENCE_EXCLUDE`, package-only) was generalized to
  `EVIDENCE_EXCLUDE` and now also applies to running capability
  evidence (systemd units/processes), not just installed packages.
- **1.5.23** — Fixed a false positive where the `libdbd-mysql-perl`
  Perl DBI driver (a pure client library) was treated as evidence of an
  installed MySQL/MariaDB server. Added to the existing client-evidence
  exclusion for the `mysql` token.
- **1.5.22** — Fixed a false positive where the MySQL/MariaDB client
  libraries/tools (`mysql-common`, `mariadb-common`, `libmysqlclient*`,
  `libmariadb*`) — commonly pulled in as a dependency by unrelated
  packages — were treated as evidence of an installed MySQL/MariaDB
  server. Introduced `PACKAGE_EVIDENCE_EXCLUDE` to exclude such
  client-only package names from installation evidence for the `mysql`
  token; genuine server packages or runtime evidence (systemd
  unit/process `mysqld`/`mariadbd`) are still detected as before.
- **1.5.21** — Fixed a false positive where mere presence of the
  `dmraid` package (openSUSE) was treated as evidence of active
  software RAID usage. Added a new usage-evidence source: the `md`
  section (`/proc/mdstat`) must report at least one array before the
  finding is raised, matching the existing LVM/ZFS/Corosync pattern.
- **1.5.20** — Fixed a false positive where the `site` token — the
  leading token of both the Checkmk-bundled `site_object_counts`
  plug-in and countless unrelated `site-*` packages (e.g. a web
  server's `site-config` vhost package) — caused a spurious "available
  plug-in" finding from pure leading-token coincidence. Added to
  `STOP_TOKENS`, same class as the existing `intel`/`watchdog` entries.
- **1.5.19** — Dropped the `mtr` finding. The package match is genuine,
  but the check_mk `mtr` plug-in requires deliberate manual setup (a
  per-host list of static target hosts, configured via a dedicated
  agent bakery rule), making mere package presence far too weak a
  signal for a missing-default finding.
- **1.5.18** — Dropped the `iptables` finding. iptables/netfilter
  tooling ships as a standard part of virtually every Linux
  distribution regardless of whether it is actually used for
  firewalling, so mere package presence carries no real compliance
  signal. Unlike the token-collision cases above, the plug-in match
  itself is genuine — it is simply not a meaningful finding, and no
  cheap usage evidence is available for it.
- **1.5.17** — Corosync package presence alone is not evidence of
  actual cluster usage (e.g. on Proxmox VE, it's a standard dependency
  installed regardless of clustering). Now requires the
  `corosync.service` systemd unit to be loaded and active before
  raising a finding, matching the existing LVM/ZFS usage-evidence
  pattern.
- **1.5.16** — Fixed a false positive where the systemd hardware-
  watchdog multiplexer unit (`watchdog-mux.service`, part of the base
  `watchdog` package, unrelated to any monitored subsystem) shared its
  leading token with the unrelated environmental-sensor plug-ins
  `watchdog_sensors*` (Watchdog Inc. weather-station hardware), causing
  a false "available plug-in(s)" finding from pure token-prefix
  coincidence. Added `watchdog` to `STOP_TOKENS`, same class as `intel`.
- **1.5.15** — Fixed a false positive where Ceph client-side tooling
  (`ceph-common`, `ceph-fuse`) was tokenized to the same canonical token as
  the actual Ceph server/daemon packages, so hosts with only client-side
  Ceph tooling installed were falsely reported as having available
  `ceph_df`/`ceph_status`/`ceph_status_mgrs` server plug-ins. Client-side
  packages now resolve to a distinct token.
- **1.5.14** — Fixed a false positive where the RabbitMQ client library
  package (`librabbitmq4`) was tokenized to the same canonical token as the
  actual `rabbitmq-server` package, incorrectly reporting an "available"
  RabbitMQ server plug-in on hosts that only have the client library
  installed. The client library now resolves to a distinct token.
- **1.5.13** — Fixed a false positive where the ISC DHCP client/common
  packages (`isc-dhcp-client`, `isc-dhcp-common`) were tokenized to the same
  canonical token as the actual `isc-dhcp-server` package, incorrectly
  reporting an "available" `isc_dhcpd` plug-in on hosts that only have the
  DHCP client installed. Client/common packages now resolve to distinct
  tokens.
- **1.5.11** — Fixed a false positive where the NFS client package
  (`nfs-common`) and its `nfs-blkmap.service` boot-time unit were tokenized
  to the same canonical token as the actual NFS server (`nfs-kernel-server`/
  `nfs-server`), incorrectly reporting an "available" NFS exports plug-in on
  pure NFS-client hosts. NFS server evidence is now derived specifically
  from the `nfs-server`/`nfs-kernel-server` systemd unit or package name.
- **1.5.9** — Kernel/library-only features (LVM, ZFS) are no longer flagged
  as an unmonitored finding merely because the package is installed or an
  always-on boot hook unit exists. We now require corroborating evidence of
  actual use from the already-collected `df` section (no extra agent
  plug-in): a mounted filesystem with `fs_type == "zfs"`, or a mounted
  LVM-managed block device (`/dev/mapper/<vg>-<lv>` or `/dev/dm-<N>`). Without
  that evidence the capability is dropped entirely, eliminating false
  positives on hosts where the package is present but never actually used.
- **1.5.8** — Fixed a false positive where the generic package/process
  tokenizer collided by coincidence: an installed package `intel-microcode`
  was tokenized to `intel`, which is also the leading token of the
  hardware-specific `intel_true_scale_*` plug-in family, so it was
  incorrectly reported as an "available plug-in" for that package. `intel`
  is now excluded via `STOP_TOKENS`, the same mechanism already used to
  filter other generic/base-OS token collisions (`cpu`, `mem`, `kernel`, ...).
- **1.5.7** — Fixed HW/SW inventory package detection: the server-side agent
  was looking for the inventory file at `var/check_mk/inventory/<host>`
  (bare/`.gz`), but modern Checkmk (>=2.2) stores it as
  `<host>.json`/`<host>.json.gz` with the actual tree nested one level
  deeper under a `raw_tree` key alongside `meta`. Both bugs meant
  `inventory_packages` always silently returned an empty list, so
  inventory-only subsystems (e.g. `apt`) were never picked up as a
  capability even though they were clearly visible in the HW/SW Inventory
  itself. Now reads `<host>.json[.gz]` (falling back to the legacy
  extension-less layout) and unwraps `raw_tree` when present.
- **1.5.6** — Fixed a remaining LVM2 false positive: `lvm2-activation-early`
  (and other distro-specific `lvm2-*` boot hooks not covered by the 1.5.5
  fixed name list) are now caught by a generic `lvm2-` prefix match instead
  of an exact-name list, since the whole `lvm2-*` unit family behaves the
  same way (always "loaded active" regardless of actual LVM usage).
- **1.5.5** — Fixed a false positive on `lvm2-monitor.service` (and its
  sibling `lvm2-lvmpolld` units): these are boot-time housekeeping units
  from the base `lvm2` package that show "loaded active" on virtually
  every Debian/Ubuntu host, even with no LVM volume group in use at all
  (unlike ZFS's import units, they have no condition that gates them on
  actual usage). They are now excluded from systemd-unit-based capability
  detection.
- **1.5.4** — Fixed false positives from the built-in `systemd_units` section:
  units are now only counted when actually present and active (loaded +
  active running, or loaded + active exited for legitimate oneshot units),
  instead of matching on unit name alone. This eliminates spurious findings
  from masked units, template unit instances (`name@instance.service`,
  e.g. `heartbeat-failed@frr.service` wrongly matching a "Heartbeat"
  capability), and units reported by systemd but not actually loaded
  (`not-found`/inactive/dead, e.g. leftover OnFailure= hooks).

