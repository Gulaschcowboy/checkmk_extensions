# checkmk_extensions

Custom [Checkmk](https://checkmk.com/) extensions (MKP plugins), one subdirectory
per package. Each subdirectory contains the plugin source tree
(`cmk_addons_plugins/<plugin>/…`), its `*.manifest.temp`, the built `.mkp`, and a
README with install and build instructions.

⚠️ Disclaimer: 
These are independent and private Checkmk extensions and not officially affiliated with or endorsed by Checkmk GmbH. 
Any issues, bugs, or incompatibilities are not in the responsibility of Checkmk GmbH and should be reported to this project's issue tracker, not to Checkmk support.

🤖 AI disclaimer: 
These plugins' code was generated with AI (LLM) assistance.
Requirements, prompting, code review, and testing against a real Checkmk
instance were performed by experienced Users. Use at your own risk.

## Packages

| Package    | Description                                                        |
|------------|--------------------------------------------------------------------|
| [`opnsense`](opnsense/) | OPNsense firewall monitoring via the REST API — firmware/update status, per-service, system/uptime/load, memory/swap, per-filesystem. |
| [`pmg`](pmg/) | Proxmox Mail Gateway monitoring via the REST API (ticket auth) — mail throughput/junk ratio, SMTP early rejects, per-queue Postfix depth, spam/virus quarantine size, ClamAV DB freshness, SpamAssassin rule updates, node status, pending package updates, subscription status, and per-certificate expiry. |
| [`proxmox_backup_server_api`](proxmox_backup_server_api/) | Proxmox Backup Server monitoring via the REST API — node CPU/load/memory/uptime/root FS, subscription, per-datastore usage with estimated-full projection, garbage collection, and configured prune/verify/sync/tape jobs. |
| [`proxmox_node_swap`](proxmox_node_swap/) | Proxmox VE node swap usage (agent-based + Agent-Bakery): monitors host swap consumption and pinpoints the QEMU VMs/LXC containers responsible, with configurable warn/crit levels and graphing. |
| [`powerdns`](powerdns/) | PowerDNS Authoritative Server and Recursor monitoring via their built-in HTTP APIs (control-socket fallback) — status/security-status, query & error rates, packet/query/record cache efficiency, answer latency, per-zone record counts & serials, and recursor DNSSEC validation. Ships an agent plugin + CEE agent-bakery rule. |
| [`dnssec_health`](dnssec_health/) | DNSSEC status monitoring for arbitrary domains via a stdlib special agent (no agent on host, no `dnspython`) — checks every configured domain against every configured resolver, reporting whether it's signed (`DNSKEY`) and validated (`AD` bit). |
| [`mail_domain_health`](mail_domain_health/) | ⚠️ **WIP** — DNS-based mail-domain security posture via a stdlib special agent (no agent on host): SPF, DMARC, DKIM, DNSBL/RBL, domain blacklists, MTA-STS/TLS-RPT, DANE/TLSA, BIMI and RDAP registration expiry, plus an overview dashboard. Incompatible changes expected. |
| [`openwb`](openwb/) | ⚠️ **WIP** — openWB wallbox monitoring via its read-only simpleAPI HTTP endpoint (auto-discovers chargepoints, counters, batteries, PV) — charging power/state, grid import/export, battery SoC, PV yield. |
| [`homeassistant`](homeassistant/) | Home Assistant special agent — reads sensor states via the REST API and area/device metadata via the WebSocket API, groups entities by area into piggyback hosts (`ha-<area>`), with configurable domain filters and safety limits on generated hosts/entities. |
| [`zfs_arc`](zfs_arc/) | ZFS ARC cache usage (agent-based + Agent-Bakery): monitors ARC size vs. `zfs_arc_max` and RAM, and hit ratio, with independently configurable warn/crit levels, an unconditional throttle-event warning, a heuristic tuning suggestion and graphing. |
| [`hermes_dashboard`](hermes_dashboard/) | [Hermes Agent](https://hermes-agent.nousresearch.com/) web dashboard monitoring via its REST API (`GET /api/status`) — overall status, gateway process state, per-platform connection status (Telegram/Discord/Slack/...), per-component health (gateway/dashboard/storage/platforms), active sessions, and pending updates. |
| [`monitoring_compliance`](monitoring_compliance/) | ⚠️ **WIP** — Capability-based detection of installed/running host subsystems that could be monitored by Checkmk but aren't yet — correlates agent sections, systemd/Windows services, processes, host labels and HW/SW inventory packages against available check plug-ins, with a persistent capability database and an informational known-catalog reference service. Detection false positives are still being found and fixed case-by-case. |

## Installing a package

Grab the `.mkp` from the package's subdirectory and, on your Checkmk site:

```
mkp add <package>-<version>.mkp
mkp enable <package> <version>
```

