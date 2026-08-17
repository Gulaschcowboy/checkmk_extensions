# Checkmk Monitoring Compliance

Detects installed and/or running services on a host that are not yet monitored,
even though a suitable Checkmk plug-in is available on the server. The result
is a **"Checkmk Monitoring Compliance"** service with WARN/CRIT logic and a
compliance metric (`compliance_percent`).

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
mkp add monitoring_compliance-1.5.3.mkp
mkp enable monitoring_compliance 1.5.3
```
