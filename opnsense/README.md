# OPNsense (REST API) — Checkmk Special Agent

Checkmk MKP that monitors OPNsense firewalls through the OPNsense REST API
(no SNMP). It polls the firewall over HTTPS using an API key/secret pair and
produces the following services:

<img width="1399" height="1126" alt="image" src="https://github.com/user-attachments/assets/12469cf3-f18a-4c41-a196-bd54de66aea4" />


| Check plugin        | Services                                              |
|---------------------|-------------------------------------------------------|
| `opnsense_firmware` | Firmware version and pending-update status            |
| `opnsense_services` | One service per OPNsense daemon (auto-discovered)     |
| `opnsense_system`   | System status, uptime and load average               |
| `opnsense_memory`   | RAM and swap usage (registered in `opnsense_system.py`)|
| `opnsense_disk`     | One service per mounted filesystem                    |
| `opnsense_smart`    | One service per physical disk (SMART health, temperature, SSD life) |
| `opnsense_temperature` | One service per temperature sensor (CPU cores, ACPI zones) |
| `opnsense_gateways` | One service per gateway (status, RTT, packet loss)    |
| `opnsense_wireguard`| One service per WireGuard peer (latest handshake age, traffic) |
| `opnsense_dhcp`     | One service per DHCPv4 pool (Kea and/or Dnsmasq lease usage) |
| `opnsense_audit`    | Known vulnerabilities in installed packages (`pkg audit`) |

All metrics reuse Checkmk's canonical names (`load1/5/15`, `mem_used`,
`swap_used`, `fs_used_percent`, `uptime`, `temp`), so the builtin graphs,
perfometers and units apply automatically (e.g. Checkmk's *CPU load* and
*RAM + Swap* graphs). The SMART check adds one plugin-specific metric,
`ssd_life_remaining`, with its own graph; WireGuard and the package audit add
`opnsense_wg_handshake_age` and `opnsense_vulnerable_packages`.

The optional checks (SMART, gateways, WireGuard, DHCP, package audit) need
additional API privileges — see
[Required API key privileges](#required-api-key-privileges). If a privilege
or the underlying OPNsense component is missing, only the affected services
are skipped or report the error; the other checks are unaffected.

## Layout

```
cmk_addons_plugins/opnsense/
├── libexec/agent_opnsense          # special agent (REST API poller)
├── agent_based/                    # check plugins (parse + evaluate sections)
│   ├── opnsense_firmware.py
│   ├── opnsense_services.py
│   ├── opnsense_system.py          # system + memory + temperature CheckPlugins
│   ├── opnsense_disk.py
│   ├── opnsense_smart.py           # SMART disk health CheckPlugin
│   ├── opnsense_gateways.py
│   ├── opnsense_wireguard.py
│   ├── opnsense_dhcp.py            # Kea + Dnsmasq DHCPv4 pools
│   └── opnsense_audit.py           # pkg audit
├── rulesets/                       # WATO rules (connection params + check params)
│   ├── opnsense.py
│   └── opnsense_params.py
├── server_side_calls/opnsense.py   # wires the ruleset to the special agent
├── graphing/                       # plugin-specific metrics
│   ├── opnsense_smart.py           # ssd_life_remaining metric + graph
│   └── opnsense_extra.py           # WireGuard handshake age, vulnerable packages
└── checkman/                       # manpages (one per check plugin)
    ├── opnsense_firmware
    ├── opnsense_services
    ├── opnsense_system
    ├── opnsense_memory
    ├── opnsense_disk
    ├── opnsense_smart
    ├── opnsense_temperature
    ├── opnsense_gateways
    ├── opnsense_wireguard
    ├── opnsense_dhcp
    └── opnsense_audit
```

## SMART disk health

`opnsense_smart` reports one service per physical disk that OPNsense's
[os-smart](https://github.com/opnsense/plugins/tree/master/sysutils/smart)
plugin can see:

- **Health** — the SMART overall-health self-assessment (`PASSED`/`FAILED`).
  The service goes to `CRIT` on `FAILED` (state configurable).
- **Temperature** — canonical `temp` metric, `WARN` at 45 °C, `CRIT` at 55 °C
  by default.
- **SSD life remaining** — `ssd_life_remaining` metric in percent, `WARN` below
  50 %, `CRIT` below 25 % by default.
- **Details** — model, serial number and power-on hours.

Data comes from the `api/smart/service/*` endpoints, which are only available
when the os-smart plugin is installed on OPNsense
(*System → Firmware → Plugins → os-smart*). If it is missing, the agent emits
an empty section and no SMART services are discovered — the other checks are
unaffected.

### Which disks are monitored

All disks reported by OPNsense's os-smart plugin are collected and
discovered — there is no device filter in the special-agent rule. To exclude
a disk you don't want monitored (e.g. a USB bridge that smartctl cannot
query), disable the resulting `opnsense_smart` service for that disk via a
normal Checkmk "disabled services" rule instead.

### Thresholds

Per-host and per-disk levels are configured under
*Setup → Services → Service monitoring rules → OPNsense disk health (SMART)*:

| Parameter                          | Default        | Meaning                                  |
|------------------------------------|----------------|------------------------------------------|
| State when SMART health is FAILED  | `CRIT`         | State when the self-assessment fails     |
| Disk temperature levels            | `45 °C / 55 °C`| `WARN`/`CRIT` upper temperature levels   |
| SSD life remaining levels          | `50 % / 25 %`  | `WARN`/`CRIT` lower life-remaining levels|

### How SSD life remaining is derived

There is no cross-vendor standard for wear, so the check prefers the most
specific source it can find:

1. **NVMe** — `nvme_smart_health_information_log.percentage_used`, reported as
   `100 - percentage_used`.
2. **ATA attribute 231 (`SSD_Life_Left`)** — semantics differ per vendor:
   Phison/PNY/Kingston-style drives put the remaining life in the *raw* value,
   Samsung-style drives put the current temperature in the raw value and the
   remaining life in the *normalized* value. The check uses the raw value when
   it is a plausible percentage that does not look like the drive temperature
   (within 5 °C), and falls back to the normalized value otherwise.
3. **ATA attribute 233 (`Media_Wearout_Indicator`)** — normalized value, used
   by Intel/Micron-style drives.

If none of these are present (spinning disks, hardware RAID, USB bridges) only
health and temperature are reported.

## Changelog

- 1.2.1: Fix [#7](https://github.com/Gulaschcowboy/checkmk_extensions/issues/7):
  - The agent no longer triggers a firmware update check (mirror probe) on
    every run, only every `--firmware-check-interval` minutes (default 120,
    new rule option *Firmware update check interval*) or when OPNsense has
    no result yet; otherwise it reads the cached status via GET.
  - Fixed a loop introduced in 1.2.0: the update check overwrote the progress
    log of a running package audit, so the audit never completed, every
    agent run waited 30 s and the audit was restarted every 15 min. No
    update check is started while an audit runs, and only the run that
    starts the audit waits for it.
  - `OPNsense Firmware` no longer reports "No updates available" when
    OPNsense has no check result at all, e.g. after a reboot (→ `UNKNOWN`) or the check
    failed (`status: error` → `UNKNOWN` with the OPNsense message). The
    service details show when OPNsense last checked and when the agent last
    triggered a check.
  - Kea and Dnsmasq are only queried if the service is enabled on OPNsense
    (from `core/service/search`, already part of every run). The lease
    queries are expensive on OPNsense even with the server unused. If the
    service list is unavailable, both are queried as before. Pools of a
    disabled DHCP server are no longer monitored; their services vanish
    after the next service discovery.
- 1.2.0: New checks ([#6](https://github.com/Gulaschcowboy/checkmk_extensions/issues/6)):
  - `opnsense_gateways` — one service per gateway with dpinger status,
    RTT and packet loss (`rta`/`pl` metrics). States per gateway status
    (down `CRIT`, loss/delay/force-down `WARN`) and optional RTT/loss levels
    are configurable via the *OPNsense gateways* rule.
  - `opnsense_wireguard` — one service per WireGuard peer with latest
    handshake age (default `WARN` 5 min / `CRIT` 15 min) and transfer
    counters. Rule: *OPNsense WireGuard peers*.
  - `opnsense_dhcp` — DHCPv4 pool usage for Kea and Dnsmasq (default
    `WARN` 80 % / `CRIT` 90 %). Rule: *OPNsense DHCP pool usage*.
  - `opnsense_audit` — known vulnerabilities in installed packages
    (`pkg audit`, default `WARN`). The audit is triggered by the special
    agent at most every 360 minutes (configurable, 0 disables it) and the
    result is cached on the Checkmk site. Rule: *OPNsense package audit*.
  - `opnsense_temperature` — one service per temperature sensor (default
    `WARN` 70 °C / `CRIT` 80 °C). Rule: *OPNsense temperature sensors*.
  - Documentation: exact OPNsense privilege names and a warning that most
    of them also grant write/action rights (firmware updates, reboot,
    service start/stop, config changes), which `System: Deny config write`
    does not fully prevent.
- 1.1.1: Remove the combined "OPNsense load average" and
  "OPNsense memory & swap" graphs ([#5](https://github.com/Gulaschcowboy/checkmk_extensions/issues/5)).
  They only referenced Checkmk's canonical metrics (`load1/5/15`, `mem_used`,
  `swap_used`), and since Checkmk binds graph templates by metric name, they
  showed up on every service emitting those metrics (e.g. *CPU load* and
  memory services of all Linux hosts). Checkmk's builtin *CPU load* and
  *RAM + Swap* graphs cover the same data. Metrics and RRD history are
  unchanged.
- 1.1.0: Add SMART disk health monitoring (`opnsense_smart`) — health
  self-assessment, temperature and SSD life remaining per physical disk,
  collected through the OPNsense os-smart plugin (`api/smart/service/*`).
  Requires the os-smart plugin and the `Services: SMART` privilege on
  OPNsense. All disks reported by os-smart are always collected — to exclude
  a disk (e.g. a USB bridge that smartctl cannot query) use a normal Checkmk
  "disabled services" rule on the resulting `opnsense_smart` service instead
  of a special-agent-side filter. Adds an `OPNsense disk health (SMART)`
  parameter rule (health state, temperature and SSD life levels) and the
  `ssd_life_remaining` metric/graph. Temperature reuses the canonical `temp`
  metric.
- 1.0.3: Fix `cmk-validate-plugins` error on `opnsense_memory`/`opnsense_disk`
  ("Default parameters ... cannot be read by referenced rule spec ...
  Unable to transform value"). The rulesets use `SimpleLevels`, which expects
  `check_default_parameters={"levels": ("fixed", (80.0, 90.0))}` (Checkmk's
  `LevelsT` tuple form), not the bare `(80.0, 90.0)` tuple used before.
  Both check functions now go through `cmk.agent_based.v2.check_levels()` so
  future rule changes stay in sync with the ruleset's value shape.

## Install

```
mkp add opnsense-1.2.1.mkp
mkp enable opnsense 1.2.1
```

Then create a host for the firewall and add a rule under
*Setup → Agents → Other integrations → OPNsense via REST API* (this MKP's
special-agent ruleset). Supply:

- **Host / address** — the firewall (IPv6 addresses are bracketed automatically).
- **API key** and **API secret** — best referenced from the Checkmk password
  store rather than typed inline, so no plaintext secret lands in the rule or
  the process list.
- **Port** — default `8443`.
- **TLS certificate check** — can be disabled for self-signed certificates.

Create an API key/secret in OPNsense under *System → Access → Users →
(edit user) → API keys*.

## Required API key privileges

The special agent only reads data, with two throttled exceptions that start
an action on the firewall. Neither changes configuration or packages:

- **Firmware update check** — POST `core/firmware/status` runs OPNsense's
  update check (*Check for updates* in the GUI), which contacts the package
  mirrors. It runs at most every `--firmware-check-interval` minutes
  (default 2 h), plus once right away when OPNsense has no check result yet
  (e.g. after a reboot). All other runs only read the cached result (GET).
  `0` never triggers a check. Rule: *Firmware update check interval*.
- **Package audit** — POST `core/firmware/audit` starts `pkg audit`, at most
  every `--audit-interval` minutes (default 6 h; `0` disables it). That run
  refreshes the vulnerability database and reads the installed packages.

Both write to the same firmware progress log on OPNsense, so the agent does
not start an update check while an audit is still running.

The API key inherits the privileges of the OPNsense user it belongs to, so
create a dedicated **monitoring user** and grant exactly the privileges below —
nothing more. Assign them under *System → Access → Users → (edit user) →
Effective Privileges* (or via a group). The names below are exactly as shown
there.

| OPNsense privilege | Covers API pattern        | Used for                                    |
|--------------------|---------------------------|---------------------------------------------|
| **System: Firmware** | `api/core/firmware/*`     | `core/firmware/status` — firmware/update status; `core/firmware/audit` + `…/upgradestatus` — package audit |
| **Status: Services** | `api/core/service/*`      | `core/service/search` — per-daemon service discovery |
| **System: Status**   | `api/core/system/status*`, `api/core/system/dismiss_status` | `core/system/status` — overall system status |
| **Lobby: Dashboard** | `api/diagnostics/system/*` (dashboard set) | `diagnostics/system/system_time`, `…/system_resources`, `…/system_disk`, `…/system_swap`, `…/system_temperature` — uptime, load, memory, swap, disk, temperature |
| **Services: SMART** *(optional)* | `api/smart/service/*` | `smart/service/list` + `smart/service/info` — per-disk SMART health, temperature and SSD life (only used when the os-smart plugin is installed) |
| **System: Gateways** *(optional)* | `api/routing/settings/*`, `api/routes/gateway/status` | `routes/gateway/status` — gateway status, RTT, loss |
| **VPN: WireGuard: Status** *(optional)* | `api/wireguard/service/*` | `wireguard/service/show` — WireGuard peers |
| **Services: DHCP: Kea(v4)** *(optional)* | `api/kea/dhcpv4/*`, `api/kea/leases4/*`, `api/kea/service/*` | `kea/dhcpv4/search_subnet`, `kea/leases4/search` — Kea DHCPv4 pool usage |
| **Services: Dnsmasq DNS/DHCP: Settings** *(optional)* | `api/dnsmasq/*` | `dnsmasq/settings/search_range`, `dnsmasq/leases/search` — Dnsmasq DHCPv4 pool usage |

> **Warning — these privileges are not read-only.** OPNsense privileges are
> URL patterns per GUI page; there is no read/write split. Every privilege in
> the table above (except *Lobby: Dashboard*) also covers write endpoints of
> the same page:
>
> | Privilege | Write actions it also allows | Blocked by *System: Deny config write*? |
> |-----------|------------------------------|------------------------------------------|
> | System: Firmware | firmware **update / upgrade**, package **install / remove / reinstall / lock**, **reboot**, **power off** | **no** |
> | Status: Services | **start / stop / restart** any service | **no** |
> | System: Status | dismiss system status notices | no |
> | Services: SMART | start / abort SMART self-tests | no |
> | System: Gateways | edit gateway configuration (`api/routing/settings/*`) | yes |
> | VPN: WireGuard: Status | WireGuard service **start / stop / restart / reconfigure** | no |
> | Services: DHCP: Kea(v4) | edit Kea subnets/reservations; Kea service **start / stop / restart** | config: yes; service: no |
> | Services: Dnsmasq DNS/DHCP: Settings | edit the whole Dnsmasq configuration; Dnsmasq service **start / stop / restart** | config: yes; service: no |
>
> Treat the API key/secret like an admin credential: store it only in the
> Checkmk password store, restrict API access to the Checkmk site (firewall
> rule on the GUI/API port), and grant only the optional privileges for the
> features you actually use. Prefer *VPN: WireGuard: Status* over
> *VPN: WireGuard: Configuration* — both cover the endpoint, but the latter
> additionally allows editing the WireGuard configuration.

Notes:
- **Lobby: Dashboard** is the privilege that exposes the read-only
  `diagnostics/system/*` gauge endpoints (they are the same ones the OPNsense
  dashboard widgets consume); no separate *Diagnostics* privilege is needed for
  the metrics this agent reads.
- **Services: SMART** is only needed if you want the `opnsense_smart` check.
  Without it the agent reports an empty SMART section and no SMART services are
  discovered — the other checks are unaffected.
- Granting **System: Deny config write** to the monitoring user in addition is
  recommended — the agent never writes configuration. It only blocks
  configuration saves, though, **not** service start/stop, firmware
  updates, reboot or power off (see the warning above).
- Privilege ↔ endpoint mapping (names, patterns and controller actions)
  verified against the `ACL.xml` files and API controllers of OPNsense core
  (`master` branch, models `Core`, `Routing`, `Wireguard`, `Kea`, `Dnsmasq`)
  and of the os-smart plugin.

## Verified against

- Checkmk 2.5.0p10 (Enterprise/CRE cmk_addons layout)
- Checkmk 2.5.0p12 (CRE)
- Checkmk 3.0.0.2026.08.03 (daily build)

Target firewall running OPNsense 26.7.x, REST API on port 8443, tested via both IPv6 and IPv4.
SMART data checked against SATA SSDs with both Phison-style and Samsung-style
attribute 231 layouts, an NVMe SSD, and a USB bridge that smartctl cannot
query.
