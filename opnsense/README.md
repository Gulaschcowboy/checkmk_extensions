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

All metrics reuse Checkmk's canonical names (`load1/5/15`, `mem_used`,
`swap_used`, `fs_used_percent`, `uptime`, `temp`), so the builtin graphs,
perfometers and units apply automatically. Two combined graphs are added on
top: OPNsense load average and OPNsense memory & swap. The SMART check adds
one plugin-specific metric, `ssd_life_remaining`, with its own graph.

## Layout

```
cmk_addons_plugins/opnsense/
├── libexec/agent_opnsense          # special agent (REST API poller)
├── agent_based/                    # check plugins (parse + evaluate sections)
│   ├── opnsense_firmware.py
│   ├── opnsense_services.py
│   ├── opnsense_system.py          # system + memory CheckPlugins
│   ├── opnsense_disk.py
│   └── opnsense_smart.py           # SMART disk health CheckPlugin
├── rulesets/                       # WATO rules (connection params + check params)
│   ├── opnsense.py
│   └── opnsense_params.py
├── server_side_calls/opnsense.py   # wires the ruleset to the special agent
├── graphing/                       # combined graphs + plugin-specific metrics
│   ├── opnsense.py                 # combined load + memory graphs
│   └── opnsense_smart.py           # ssd_life_remaining metric + graph
└── checkman/                       # manpages (one per check plugin)
    ├── opnsense_firmware
    ├── opnsense_services
    ├── opnsense_system
    ├── opnsense_memory
    ├── opnsense_disk
    └── opnsense_smart
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

The special-agent rule has an optional **SMART devices to monitor** field: a
regular expression matched against the OPNsense device names, so a box with
USB bridges that smartctl cannot talk to does not produce UNKNOWN services.

| Value       | Effect                                       |
|-------------|----------------------------------------------|
| `.*`        | All devices (default)                        |
| `ada0`      | Only `ada0`                                  |
| `^ada`      | All `ada*` devices                           |
| `ada0\|nvme0` | `ada0` or `nvme0`                          |

Non-matching devices are neither queried nor discovered.

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

- 1.1.0: Add SMART disk health monitoring (`opnsense_smart`) — health
  self-assessment, temperature and SSD life remaining per physical disk,
  collected through the OPNsense os-smart plugin (`api/smart/service/*`).
  Requires the os-smart plugin and the `Services: SMART` privilege on
  OPNsense. Adds an optional **SMART devices to monitor** regular expression
  to the special-agent rule, an `OPNsense disk health (SMART)` parameter rule
  (health state, temperature and SSD life levels) and the
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
mkp add opnsense-1.1.0.mkp
mkp enable opnsense 1.1.0
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
- **SMART devices to monitor** — optional regular expression selecting the
  disks to poll for SMART data (see the *SMART disk health* section), default
  `.*`.

Create an API key/secret in OPNsense under *System → Access → Users →
(edit user) → API keys*.

## Required API key privileges

The special agent only ever performs **read-only** calls (GET, or POST without
writing state). The API key inherits the privileges of the OPNsense user it belongs
to, so create a dedicated **read-only monitoring user** and grant exactly the
privileges below — nothing more. Assign them under *System → Access → Users →
(edit user) → Effective Privileges* (or via a group).

| OPNsense privilege | Covers API pattern        | Used for                                    |
|--------------------|---------------------------|---------------------------------------------|
| **System: Firmware** | `api/core/firmware/*`     | `core/firmware/status` — firmware/update status |
| **Status: Services** | `api/core/service/*`      | `core/service/search` — per-daemon service discovery |
| **System: Status**   | `api/core/system/status*` | `core/system/status` — overall system status |
| **Lobby: Dashboard** | `api/diagnostics/system/*` (dashboard set) | `diagnostics/system/system_time`, `…/system_resources`, `…/system_disk`, `…/system_swap`, `…/system_temperature` — uptime, load, memory, swap, disk, temperature |
| **Services: SMART** *(optional)* | `api/smart/service/*` | `smart/service/list` + `smart/service/info` — per-disk SMART health, temperature and SSD life (only used when the os-smart plugin is installed) |

Notes:
- **Lobby: Dashboard** is the privilege that exposes the read-only
  `diagnostics/system/*` gauge endpoints (they are the same ones the OPNsense
  dashboard widgets consume); no separate *Diagnostics* privilege is needed for
  the metrics this agent reads.
- **Services: SMART** is only needed if you want the `opnsense_smart` check.
  Without it the agent reports an empty SMART section and no SMART services are
  discovered — the other checks are unaffected.
- Granting **System: Deny config write** to the monitoring user in addition is a
  reasonable hardening step — the agent never writes configuration.
- Privilege ↔ endpoint mapping verified against OPNsense core `ACL.xml`
  (`OPNsense/Core/ACL/ACL.xml`) on the `master` branch. The `api/smart/*`
  mapping comes from the ACL definition shipped with the os-smart plugin.

## Verified against

- Checkmk 2.5.0p10 (Enterprise/CRE cmk_addons layout)
- Checkmk 2.5.0p12 (CRE)
- Checkmk 3.0.0.2026.08.03 (daily build)

Target firewall running OPNsense 26.7.x, REST API on port 8443, tested via both IPv6 and IPv4.
SMART data checked against SATA SSDs with both Phison-style and Samsung-style
attribute 231 layouts, an NVMe SSD, and a USB bridge that smartctl cannot
query.
