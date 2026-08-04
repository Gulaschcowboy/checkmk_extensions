# Proxmox Backup Server (REST API)

Checkmk special agent + check plugins that monitor a
[Proxmox Backup Server](https://www.proxmox.com/en/proxmox-backup-server) (PBS)
through its REST API (default port 8007, API-token authentication).

### This is not a replacement for monitoring via the Checkmk agent, but an addition to the deployed agent.

## What it monitors

One host runs the special agent against the PBS API; services are auto-discovered:

| Service | Description |
|---|---|
| `PBS Node` | CPU utilization, load average, uptime |
| `PBS Node Memory` | RAM and swap usage |
| `PBS Node Root FS` | Root filesystem usage |
| `PBS Subscription` | Subscription/support status |
| `PBS Datastore <name>` | Per-datastore usage + PBS estimated-full projection (one per datastore) |
| `PBS GC <datastore>` | Garbage collection: schedule, last result, reclaimed space, bad chunks (one per datastore) |
| `PBS Job <type> <id>` | Configured prune / verify / sync / tape jobs, each with its last run result (one per job) |

## Requirements

- Checkmk 2.3.0b1 or newer (uses the `cmk_addons_plugins` API v2 layout).
- A PBS API token with read-only audit privileges — role `Audit` on path `/`
  (privileges `Datastore.Audit` + `Sys.Audit`) is sufficient. Create it under
  **Configuration > Access Control > API Token** in the PBS UI.

## Authentication note

PBS uses a different HTTP auth header than Proxmox VE. The special agent sends:

```
Authorization: PBSAPIToken=<token-id>:<token-secret>
```

(Using `PVEAPIToken` — the PVE form — fails with "authentication failed".)

## Installation

```sh
mkp add proxmox_backup_server_api-1.0.0.mkp
mkp enable proxmox_backup_server_api 1.0.0
```

Then in Checkmk:

1. Create a host for the PBS server.
2. Add the rule **Setup > Agents > Other integrations > Proxmox Backup Server (REST API)**.
3. Enter the API token ID and token secret (the secret may reference the
   password store), adjust port / node name / TLS check as needed.
4. Run service discovery and activate changes.

## Configuration options (WATO ruleset)

- **API token ID** — e.g. `root@pam!checkmk`
- **API token secret** — supports the Checkmk password store
- **HTTPS port** — default `8007`
- **PBS node name** — default `localhost` (single-node installs)
- **Task history scan depth** — how many recent tasks to correlate job/GC results from
- **Disable TLS certificate verification** — for self-signed certs (default on)
- **Request timeout**

## Building from source

From this directory:

```sh
python3 ../../tools/build_mkp.py
python3 ../../tools/verify_mkp.py . proxmox_backup_server_api-1.0.0.mkp agent_proxmox_backup_server_api
```

## Layout

```
cmk_addons_plugins/proxmox_backup_server_api/
  agent_based/        proxmox_backup_server_api_{node,datastore,gc,jobs}.py
  checkman/           manpages for each check
  graphing/           PBS-specific metrics/graphs (GC & jobs)
  libexec/            agent_proxmox_backup_server_api  (the special agent)
  rulesets/           special-agent + check-parameter rulesets
  server_side_calls/  builds the agent command line
proxmox_backup_server_api.manifest.temp
proxmox_backup_server_api-1.0.0.mkp
```
