# ZFS ARC cache usage — Checkmk MKP (agent-based + bakery)

Checkmk MKP that monitors the **ZFS Adaptive Replacement Cache (ARC)** on a
Linux host with ZFS installed.

This is the **agent-based + Agent-Bakery successor** of the former `zfs_arc`
*local check* (≤ 0.0.4), which was implemented as a shell script doing
arithmetic via `awk`/`bc`. That approach had a real, reproducible bug: in a
comma-decimal locale (e.g. `de_DE`), `awk` printed values like `"100,0"`
instead of `"100.0"`, which made the subsequent `bc -l` call fail with a
syntax error — silently disabling the hit-ratio WARN/CRIT thresholds. The
monitoring logic now lives in a proper Python server-side check plug-in
(no shell, no `awk`/`bc`, no locale dependency at all); the host only ships a
lightweight Python agent plug-in that collects raw numbers via stdlib file
reads.

| Component | Purpose |
|-----------|---------|
| `agents/zfs_arc` | Agent plug-in. Emits one JSON section `<<<zfs_arc>>>` (`size`, `c_max`, `c_min`, `hits`, `misses`, `memory_throttle_count` from `/proc/spl/kstat/zfs/arcstats`, plus `mem_total` from `/proc/meminfo`). Emits nothing on a host without a ZFS ARC. |
| `agent_based/zfs_arc.py` | Section parser + check plug-in. Service `ZFS ARC cache usage`. |
| `rulesets/zfs_arc.py` | Check-parameter ruleset — independent warn/crit levels on ARC-vs-max %, ARC-vs-RAM % and (inverted) hit ratio %. |
| `rulesets/agent_config_zfs_arc.py` | Agent-Bakery ruleset (deploy on/off). |
| `bakery/bakery_plugin_zfs_arc.py` | Bakery plug-in (v2 API) that installs the agent plug-in. |
| `graphing/zfs_arc.py` | Metrics (`zfs_arc_used_percent`, `zfs_arc_ram_percent`, `zfs_arc_hit_ratio`, `zfs_arc_size_bytes`), a perf-o-meter and a graph. |
| `checkman/zfs_arc` | Man page. |

The service state is derived from three independently configurable level
pairs (defaults: ARC-vs-max WARN 90 % / CRIT 97 %, ARC-vs-RAM WARN 40 % /
CRIT 60 %, hit ratio WARN below 85 % / CRIT below 75 %). An ARC memory
throttle event count greater than zero always raises the state to at least
WARN. The service details additionally show a heuristic `zfs_arc_max` tuning
suggestion — advisory only, never influences the state.

The agent plug-in runs **synchronously** with each agent run — reading two
small `/proc` files is effectively free, no caching needed. On a host
without a ZFS ARC (module not loaded / no pool imported), it prints nothing,
so no service is discovered there — no permanent "not available" CRIT.

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
  (previously a shell-based local check, versions 0.0.3/0.0.4). Fixes the
  locale-dependent hit-ratio threshold bug by moving all arithmetic from
  `awk`/`bc` into Python. Adds independently configurable levels for
  ARC-vs-max, ARC-vs-RAM and hit ratio (previously hardcoded in the shell
  script), an unconditional throttle-event WARN, graphing, a perf-o-meter
  and Agent Bakery support.

## License

GPLv2.
