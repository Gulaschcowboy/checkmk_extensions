# Proxmox Backup Server (REST API)

Checkmk special agent + check plugins for monitoring a
[Proxmox Backup Server](https://www.proxmox.com/en/proxmox-backup-server) (PBS)
through its REST API (port 8007) using an API token.

Package name: `pbs` · Version: `1.0.0` · Requires Checkmk `2.3.0b1`+
(2.3 / 2.4 addon layout, `cmk_addons`).

## What it monitors

| Service                          | Check                                                                                      |
|----------------------------------|--------------------------------------------------------------------------------------------|
| `PBS Node`                       | CPU utilization, load average (1/5/15), uptime                                             |
| `PBS Node Memory`                | RAM and swap usage                                                                          |
| `PBS Node Root FS`               | Root filesystem usage                                                                       |
| `PBS Subscription`               | Subscription status (`active` / `notfound` / …)                                             |
| `PBS Datastore <name>`           | Per-datastore disk usage + PBS estimated-full-date projection (one service per datastore)  |
| `PBS GC <datastore>`             | Garbage collection: schedule, next run, last result, reclaimed space/chunks, bad chunks    |
| `PBS Job <id>`                   | Configured prune / verify / sync / tape jobs — last run result correlated from task history (one service per job) |

Datastores, GC checks and jobs are auto-discovered (one service each).

## Requirements on the PBS side

Create an API token (Datacenter → Access Control → API Tokens), e.g.
`root@pam!checkmk`, and give it at least read access
(`Datastore.Audit`, `Sys.Audit`, `Tape.Audit` if you use tape jobs).

The agent authenticates with the PBS-specific header
`Authorization: PBSAPIToken=<token-id>:<secret>` (note: **not** the
`PVEAPIToken` form used by Proxmox VE).

## Installing

On your Checkmk site:

```
mkp add pbs-1.0.0.mkp
mkp enable pbs 1.0.0
```

Then in the GUI:

1. **Setup → Agents → Other integrations → Proxmox Backup Server (REST API)** —
   create a rule for your PBS host. Enter the token ID (`user@realm!tokenname`)
   and the token secret (store it in the password store), optionally adjust the
   port (default 8007), node name (default `localhost`), timeout, task history
   limit, and TLS certificate check (disable for self-signed certs).
2. Add the PBS host (agent type: *API integrations / special agent*), then run a
   service discovery.

Check levels (datastore usage, estimated-full warning, node CPU/load/memory,
root FS, GC age, job age/result) are configurable via the corresponding
**Setup → Service monitoring rules** entries.

## Building from source

The plugin source lives under `cmk_addons_plugins/pbs/`. To rebuild the `.mkp`
with the stdlib-only build tool from this workbench:

```
python3 tools/build_mkp.py      # run from the project dir holding pbs.manifest.temp
python3 tools/verify_mkp.py . pbs-1.0.0.mkp agent_pbs
```

## Layout

```
proxmox_backup_server_api/
├── cmk_addons_plugins/pbs/
│   ├── libexec/agent_pbs              # special agent (stdlib only)
│   ├── agent_based/                   # pbs_node, pbs_datastore, pbs_gc, pbs_jobs
│   ├── rulesets/                      # pbs (agent), pbs_params (check levels)
│   ├── server_side_calls/pbs.py       # builds the agent command line
│   ├── graphing/pbs.py                # metrics/graphs
│   └── checkman/                      # man pages
├── pbs.manifest.temp
├── pbs-1.0.0.mkp
└── README.md
```
