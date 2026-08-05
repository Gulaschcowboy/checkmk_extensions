# checkmk_extensions

Custom [Checkmk](https://checkmk.com/) extensions (MKP plugins), one subdirectory
per package. Each subdirectory contains the plugin source tree
(`cmk_addons_plugins/<plugin>/…`), its `*.manifest.temp`, the built `.mkp`, and a
README with install and build instructions.

## Packages

| Package    | Description                                                        |
|------------|--------------------------------------------------------------------|
| [`opnsense`](opnsense/) | OPNsense firewall monitoring via the REST API — firmware/update status, per-service, system/uptime/load, memory/swap, per-filesystem. |
| [`proxmox_backup_server_api`](proxmox_backup_server_api/) | Proxmox Backup Server monitoring via the REST API — node CPU/load/memory/uptime/root FS, subscription, per-datastore usage with estimated-full projection, garbage collection, and configured prune/verify/sync/tape jobs. |
| [`powerdns`](powerdns/) | PowerDNS Authoritative Server and Recursor monitoring via their built-in HTTP APIs (control-socket fallback) — status/security-status, query & error rates, packet/query/record cache efficiency, answer latency, per-zone record counts & serials, and recursor DNSSEC validation. Ships an agent plugin + CEE agent-bakery rule. |

## Installing a package

Grab the `.mkp` from the package's subdirectory and, on your Checkmk site:

```
mkp add <package>-<version>.mkp
mkp enable <package> <version>
```

## Layout convention

```
<package>/
├── cmk_addons_plugins/<package>/   # plugin source (agent_based, rulesets, etc.)
├── <package>.manifest.temp         # MKP manifest (files list + version)
├── <package>-<version>.mkp         # built package
└── README.md
```

Modern Checkmk (2.3+) addon layout: plugins install to
`~/local/lib/python3/cmk_addons/plugins/<package>/` on a site.
