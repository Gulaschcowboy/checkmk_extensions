# Proxmox Backup Server (REST API)

### This is not meant as a replacement for monitoring via the Checkmk agent, but as an addition to fetch more information.

Checkmk special agent + check plugins that monitor a
[Proxmox Backup Server](https://www.proxmox.com/en/proxmox-backup-server) (PBS)
through its REST API (default port 8007, API-token authentication).

## What it monitors

One host runs the special agent against the PBS API; services are auto-discovered:
<img width="1350" height="447" alt="image" src="https://github.com/user-attachments/assets/fb744c77-40af-4a54-8080-ebe113011f38" />


| Service | Description |
|---|---|
| `PBS Node` | CPU utilization, load average, uptime |
| `PBS Node Memory` | RAM and swap usage |
| `PBS Node Root FS` | Root filesystem usage |
| `PBS Subscription` | Subscription/support status |
| `PBS Datastore <name>` | Per-datastore usage + PBS estimated-full projection (one per datastore) |
| `PBS GC <datastore>` | Garbage collection: schedule, last result, last runtime, reclaimed space, bad chunks (one per datastore) |
| `PBS Job <type> <id>` | Configured prune / verify / sync / tape jobs, each with its last run result (one per job) |
| `PBS Backup Age <datastore>[, Namespace: <ns>]` | Freshness of backups: age of the newest snapshot per backup group (VM/CT/host), one service per datastore and per datastore+namespace |

## Requirements

- Checkmk 2.3.0b1 or newer (uses the `cmk_addons_plugins` API v2 layout).
- A PBS User **AND** API token with Roles `Audit` and also `RemoteAudit`, if sync jobs should be monitored as well.
  Both on path `/` and with propagation set to yes. See screenshot below.
  Create them under
  **Configuration > Access Control > API Token** in the PBS UI.
  Then add the token and it's permission under **Configuration > Access Control > Permissions**

  <img width="800" height="291" alt="image" src="https://github.com/user-attachments/assets/c71ec53d-052f-47b4-8441-b4214d2e919c" />


## Installation

```sh
mkp add proxmox_backup_server_api-1.1.4.mkp
mkp enable proxmox_backup_server_api 1.1.4
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

### Backup Age (Freshness) check parameters

The `PBS Backup Age` service has its own two rulesets:

- **PBS backup age discovery** — which datastores are discovered (all / regex /
  explicit list) and whether per-namespace services are created.
- **PBS backup age** (check parameters):
  - **Warning / Critical age** — thresholds for the newest snapshot per group
    (default 2 / 10 days). Groups that trip a threshold are named with their age
    in the summary, e.g. `2 backups older than 10 days: vm/307 (291d), vm/100 (15d)`.
  - **Do not raise alerts** — report-only mode (state stays OK).
  - **Ignore backups older than** — backups older than this are treated as
    abandoned and no longer alert. They remain visible in the service details
    flagged with `(ignored by rule)`, but do not affect the state or summary.
  - **Ignore these groups** — exclude individual groups entirely (neither counted
    nor shown). Accepts one regular expression per line, matched against the group
    key with the usual Checkmk infix behaviour (`vm/` for all VMs,
    `vm/(9000|9001)` for a set, `^ct/300$` for exactly one).

## Layout

```
cmk_addons_plugins/proxmox_backup_server_api/
  agent_based/        proxmox_backup_server_api_{node,datastore,gc,jobs,snapshots}.py
  checkman/           manpages for each check
  graphing/           PBS-specific metrics/graphs (GC & jobs)
  libexec/            agent_proxmox_backup_server_api  (the special agent)
  rulesets/           special-agent + check-parameter rulesets
  server_side_calls/  builds the agent command line
proxmox_backup_server_api.manifest.temp
proxmox_backup_server_api-1.1.4.mkp
```
