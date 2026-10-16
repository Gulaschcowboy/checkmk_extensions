# Commvault (via REST API)

Special agent for a Commvault CommServe, using its REST API (Command Center API).

> **Beta:** This is a beta version. Incompatible changes are expected before
> 1.0.0 (API base URL settings, job types in the active jobs rule); affected
> rules may have to be re-created.

## What it monitors
<img width="1932" height="865" alt="grafik" src="https://github.com/user-attachments/assets/3a2b7897-9179-42e1-8efe-b74dcbff192c" />

<img width="2182" height="77" alt="grafik" src="https://github.com/user-attachments/assets/8f9c3420-c019-4c45-94f1-c6aad42751aa" />


| Service | Content |
|---------|---------|
| `Commvault CommServe` | Result of the agent run: login, CommServe host name and version, errors of single API query groups (a failed group makes its services UNKNOWN), truncated job list, skipped jobs, agent run time |
| `Commvault Job <subclient>` | Last backup job per subclient within the lookback period: state mapping per job status (configurable), running jobs with progress and runtime, optional age of the last successful job. SQL transaction log jobs are evaluated separately in the same service (own status and age levels, default WARN 6 h / CRIT 12 h). |
| `Commvault Active Jobs` | Currently active jobs with runtime (levels in general and per job type) and wait/pending reason |
| `Commvault Storage Pool <name>` | Storage pool status and capacity, using Checkmk's filesystem levels and trends |
| `Commvault VMs` | Summary of the virtual machines known to Commvault: number of VMs per SLA and protection status |
| `Commvault VM Backup` | Piggyback service per protected VM: SLA status, protection status, last backup with failure reason, optional age of the last successful backup |
| `Commvault MediaAgent <name>` | MediaAgent online/offline status with offline reason, unlicensed MediaAgents |
| `Commvault License` | License mode and expiry, over capacity / grace period flags |
| `Commvault License <type>` | Usage per license type |

Item format of the job services:
`<client> / <agent> [/ <instance>] [/ <backup set>] / <subclient>` (default
instance and default backup set are omitted). Restore jobs and jobs without a
subclient (aux copy, DDB, data aging) are ignored.

### Piggyback

The special agent delivers piggyback data for one service per VM; the host name
is the VM name (characters other than letters, digits, dot, dash and
underscore replaced by `_`).
Use "Hostname translation for piggybacked hosts" if your host names
differ from the VM names.

## Requirements

- Checkmk 2.3.0 or later (tested with Checkmk 3.0.0-daily)
- Commvault CommServe with REST API, tested with 11 SP44
- A Commvault user with read access to the queried entities

## Installation

```bash
mkp add commvault_rest-0.9.0.mkp
mkp enable commvault_rest 0.9.0
```

## Configuration

1. Create a host for the CommServe
2. **Setup > Agents > Other integrations > Commvault (via REST API)**:
   - API base URL, e.g. `https://commserve.example.com/commandcenter/api`
     (no trailing slash)
   - user and password
   - optional: TLS verification, request timeout, job lookback period
     (default 7 days), page size
   - data to fetch: jobs, storage pools, VM summary, piggyback data per VM,
     MediaAgents, license
   - optional: ignore "Distributed Data Platforms" jobs (Index Server backups)
3. Run the service discovery on the CommServe host.

Service rules (**Setup > Services > Service monitoring rules**):
"Commvault jobs per subclient", "Commvault active jobs", "Commvault VM
summary", "Commvault VM backup", "Commvault MediaAgents", "Commvault license",
"Commvault license usage". Storage pools use the standard "Filesystems (used
space and growth)" rule.

## Changelog

- **0.9.0** — first release (beta, see note above).
