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
| [`citrix_ddc_rest`](citrix_ddc_rest/) | Citrix Virtual Apps and Desktops (CVAD, formerly XenApp/XenDesktop) monitoring via the on-premises REST API (Citrix Orchestration Service), instead of running Checkmk's `citrix_farm.ps1` and all it's configuration hassle. Reuses Checkmk's built-in `citrix_state`, `citrix_serverload`, `citrix_sessions` and `citrix_hostsystem` checks unchanged. |
| [`commvault_rest`](commvault_rest/) | Commvault backup monitoring via the CommServe REST API (special agent) — last backup job per subclient with configurable job states, active jobs with runtime levels and wait reason, storage pool status and capacity (filesystem levels and trends), VM summary and one piggyback service per VM with SLA and protection status, MediaAgent status, license expiry and usage per license type. Beta (0.9.0): incompatible changes are expected before 1.0.0. |
| [`fortigate_vpn_tunnels`](fortigate_vpn_tunnels/) | Fortinet FortiGate IPsec VPN monitoring via SNMP with one service per tunnel (phase 2 selector) instead of the built-in summary service — up/down state (configurable per tunnel, e.g. for on-demand tunnels), remote gateway, selectors, SA lifetime and phase 1 traffic. |
| [`linotp_rest`](linotp_rest/) | LinOTP two-factor authentication server monitoring via its JSONRPC admin/monitoring API — token counts and per-resolver user counts per realm (with configurable levels), storage encryption, config sync, and license/support status including LinOTP's grace-limit message. |
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
| [`unbound`](unbound/) | Unbound checks und statistics (agent-based + bakery): monitors the unbound caching/validating DNS resolver via agent plugin — answer rates by rcode, cache hit ratio/miss rate and unwanted reply rate. Agent plugin with bakery rule for Linux; needs manual deployment on *BSD, e.g. OPNsense. |
| [`xenserver`](xenserver/) | Citrix XenServer and XCP-ng monitoring via the XAPI management API (read-only special agent, no agent on the hypervisors) — pool members and HA, alerts, storage repositories (capacity, I/O, attach state, multipath), plus piggyback data per hypervisor host (CPU, memory, interfaces, license, updates, certificates) and per VM (power state, CPU, memory, disks, NICs, snapshots, guest tools). |

## Installing a package

Grab the `.mkp` from the package's subdirectory and, on your Checkmk site:

```
mkp add <package>-<version>.mkp
mkp enable <package> <version>
```



