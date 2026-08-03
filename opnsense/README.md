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

## Build from source

The build/verify scripts live in the Hermes `checkmk-mkp-plugins` skill and are
stdlib-only (no `mkp` binary required):

```
python3 build_mkp.py      # reads opnsense.manifest.temp -> opnsense-<version>.mkp
python3 verify_mkp.py . opnsense-<version>.mkp <any-file-to-assert-present>
```

Bump `version` in `opnsense.manifest.temp` and keep the `files` list in sync when
adding or removing plugin files.

## Verified against

Checkmk 2.5.0p10 (Enterprise/CRE cmk_addons layout). Target firewall running
OPNsense 26.7.x, IPv6-only, REST API on port 8443.
