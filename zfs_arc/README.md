# ZFS ARC cache usage

## What it monitors
Checkmk MKP that monitors the **ZFS Adaptive Replacement Cache (ARC)** on a
Linux host with ZFS installed and in use.
<img width="999" height="71" alt="image" src="https://github.com/user-attachments/assets/cedb551e-a6fc-4216-b52d-45ed0ee819a9" />



The agent plug-in runs **synchronously** with each agent run — reading two
small `/proc` files is effectively free, no caching needed. On a host
without a ZFS ARC (module not loaded / no pool imported), it prints nothing,
so no service is discovered there.

## Requirements

- Checkmk 2.3.0 or newer (uses `cmk.agent_based.v2`, `cmk.rulesets.v1`,
  `cmk.graphing.v1`).
- Python 3 on the monitored host (standard on all current Linux
  distributions with ZFS support).
- The Agent Bakery (bakery plug-in) requires a **commercial edition**
  (Enterprise / Cloud / MSP). The check itself works on Raw too — you just
  deploy the agent plug-in manually there.

## Installation

```bash
mkp add zfs_arc-1.0.0.mkp
mkp enable zfs_arc 1.0.0
```

### Deploy the agent plug-in

**With the bakery (recommended):** create a rule under
*Setup → Agents → Agent rules → ZFS ARC cache usage*, bake and sign the
agent, and roll it out to the ZFS host(s).

**Manually (any edition):**

```bash
# on the ZFS host
cp zfs_arc /usr/lib/check_mk_agent/plugins/zfs_arc
chmod +x /usr/lib/check_mk_agent/plugins/zfs_arc
# test:
/usr/lib/check_mk_agent/plugins/zfs_arc
```

Then on the Checkmk server, rediscover the host — the `ZFS ARC cache usage`
service appears (only on hosts that actually have a ZFS ARC).

## Changelog

- **1.0.0** — Rebuilt from scratch as an agent-based + bakery plug-in
  (previously a shell-based local check). Fixes the
  locale-dependent hit-ratio threshold bug by moving all arithmetic from
  `awk`/`bc` into Python. Adds independently configurable levels for
  ARC-vs-max, ARC-vs-RAM and hit ratio (previously hardcoded in the shell
  script), an unconditional throttle-event WARN, graphing, a perf-o-meter
  and Agent Bakery support.

## License

GPLv2.
