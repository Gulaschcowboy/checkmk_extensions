# OPNsense (REST API) — Checkmk Special Agent

Checkmk MKP that monitors OPNsense firewalls through the OPNsense REST API
(no SNMP). It polls the firewall over HTTPS using an API key/secret pair and
produces the following services:

| Check plugin        | Services                                              |
|---------------------|-------------------------------------------------------|
| `opnsense_firmware` | Firmware version and pending-update status            |
| `opnsense_services` | One service per OPNsense daemon (auto-discovered)     |
| `opnsense_system`   | System status, uptime and load average               |
| `opnsense_memory`   | RAM and swap usage (registered in `opnsense_system.py`)|
| `opnsense_disk`     | One service per mounted filesystem                    |

All metrics reuse Checkmk's canonical names (`load1/5/15`, `mem_used`,
`swap_used`, `fs_used_percent`, `uptime`), so the builtin graphs, perfometers
and units apply automatically. Two combined graphs are added on top:
OPNsense load average and OPNsense memory & swap.

## Layout

```
cmk_addons_plugins/opnsense/
├── libexec/agent_opnsense          # special agent (REST API poller)
├── agent_based/                    # check plugins (parse + evaluate sections)
│   ├── opnsense_firmware.py
│   ├── opnsense_services.py
│   ├── opnsense_system.py          # system + memory CheckPlugins
│   └── opnsense_disk.py
├── rulesets/                       # WATO rules (connection params + check params)
│   ├── opnsense.py
│   └── opnsense_params.py
├── server_side_calls/opnsense.py   # wires the ruleset to the special agent
├── graphing/opnsense.py            # combined load + memory graphs
└── checkman/                       # manpages (one per check plugin)
    ├── opnsense_firmware
    ├── opnsense_services
    ├── opnsense_system
    ├── opnsense_memory
    └── opnsense_disk
```

## Install

```
mkp add opnsense-1.0.2.mkp
mkp enable opnsense 1.0.2
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

The special agent only ever performs **read-only** calls (GET, or POST with an
empty body). The API key inherits the privileges of the OPNsense user it belongs
to, so create a dedicated **read-only monitoring user** and grant exactly the four
privileges below — nothing more. Assign them under *System → Access → Users →
(edit user) → Effective Privileges* (or via a group).

| OPNsense privilege | Covers API pattern        | Used for                                    |
|--------------------|---------------------------|---------------------------------------------|
| **System: Firmware** | `api/core/firmware/*`     | `core/firmware/status` — firmware/update status |
| **Status: Services** | `api/core/service/*`      | `core/service/search` — per-daemon service discovery |
| **System: Status**   | `api/core/system/status*` | `core/system/status` — overall system status |
| **Lobby: Dashboard** | `api/diagnostics/system/*` (dashboard set) | `diagnostics/system/system_time`, `…/system_resources`, `…/system_disk`, `…/system_swap`, `…/system_temperature` — uptime, load, memory, swap, disk, temperature |

Notes:
- **Lobby: Dashboard** is the privilege that exposes the read-only
  `diagnostics/system/*` gauge endpoints (they are the same ones the OPNsense
  dashboard widgets consume); no separate *Diagnostics* privilege is needed for
  the metrics this agent reads.
- Granting **System: Deny config write** to the monitoring user in addition is a
  reasonable hardening step — the agent never writes configuration.
- Privilege ↔ endpoint mapping verified against OPNsense core `ACL.xml`
  (`OPNsense/Core/ACL/ACL.xml`) on the `master` branch.

## Verified against

- Checkmk 2.5.0p10 (Enterprise/CRE cmk_addons layout)
- Checkmk 3.0.0.2026.08.03 (daily build)

Target firewall running OPNsense 26.7.x, REST API on port 8443, tested via both IPv6 and IPv4.
