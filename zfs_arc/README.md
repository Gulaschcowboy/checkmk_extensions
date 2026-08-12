# ZFS ARC Cache Usage — Checkmk MKP (local check)

Checkmk MKP that monitors the **ZFS Adaptive Replacement Cache (ARC)** on a
Linux host running OpenZFS, via a Checkmk **local check** script.

| Component | Purpose |
|-----------|---------|
| `agents/custom/zfs_arc/lib/local/zfs_arc.sh` | Local check. Reads `/proc/spl/kstat/zfs/arcstats` and `/proc/meminfo`, computes ARC-vs-max %, ARC-vs-RAM %, hit ratio, and prints the `ZFS_ARC` service line (state + metrics + a tuning recommendation). |
| `agents/custom/zfs_arc/lib/plugins/zfs_arc_cache` | Agent plug-in that emits the raw `arcstats` kstat values as a `<<<zfs_arc_cache>>>` section, for anyone who wants to build additional checks on the raw counters. No check plugin in this package currently parses that section. |
| `cmk_addons_plugins/zfs_arc/checkman/zfs_arc` | Man page for the `ZFS ARC` service. |

## How it works

The local check computes:

- **ARC / c_max %** — current ARC size relative to its configured maximum.
- **ARC / RAM %** — current ARC size relative to total system memory.
- **Hit ratio** — `hits / (hits + misses)` in percent.
- **memory_throttle_count** — nonzero means the kernel has throttled ARC
  growth due to memory pressure.

State logic (fixed thresholds in the script):

| Condition | Result |
|-----------|--------|
| ARC/c_max > 90% | WARN |
| ARC/RAM > 40% | WARN |
| ARC/RAM > 60% | CRIT |
| Hit ratio < 85% | WARN |
| Hit ratio < 75% | CRIT |
| `memory_throttle_count` > 0 | WARN |

The service summary also includes a heuristic recommendation (e.g. reduce or
raise `zfs_arc_max`) based on the observed sizing and hit ratio — a starting
point for manual tuning, not applied automatically.

On hosts without ZFS (no `/proc/spl/kstat/zfs/arcstats`), the check reports
UNKNOWN and exits without further output.

## Requirements

- A Linux host running OpenZFS (kernel module exposing
  `/proc/spl/kstat/zfs/arcstats`).
- `awk` and `bc` available in the agent's `PATH`.
- Checkmk 2.3.0 or newer.

## Installation

```bash
mkp add zfs_arc-0.0.3.mkp
mkp enable zfs_arc 0.0.3
```

### Deploy the local check

```bash
# on the monitored host
cp agents/custom/zfs_arc/lib/local/zfs_arc.sh /usr/lib/check_mk_agent/local/zfs_arc.sh
chmod +x /usr/lib/check_mk_agent/local/zfs_arc.sh
# optional: raw arcstats section for custom checks
cp agents/custom/zfs_arc/lib/plugins/zfs_arc_cache /usr/lib/check_mk_agent/plugins/zfs_arc_cache
chmod +x /usr/lib/check_mk_agent/plugins/zfs_arc_cache
# test:
/usr/lib/check_mk_agent/local/zfs_arc.sh
```

Then on the Checkmk server, rediscover the host — the `ZFS ARC` service
appears.

## Changelog

- **0.0.3**: fixed the `zfs_arc_cache` plugin's file check, which was
  inverted (`[ ! -x ... ]` instead of `[ -f ... ]`) and only ever emitted
  the section by accident because `/proc` files are never executable; added
  division-by-zero guards to `zfs_arc.sh` for `c_max`/`mem_total`/hit-ratio
  on a freshly booted or idle ARC.
- **0.0.2**: initial version, packaged from a standalone local check.

## License

GPLv2.
