#!/usr/bin/env python3
"""Graphing for the Proxmox Backup Server checks.

The node/datastore checks reuse Checkmk's canonical metric names (util,
io_wait, load1/5/15, uptime, mem_used, mem_used_percent, swap_used, fs_used,
fs_used_percent, fs_free) which already carry builtin definitions and graphs —
we must NOT redefine those (duplicate registration breaks plugin loading).

Here we only define the PBS-specific metrics emitted by the GC and job checks,
plus a couple of grouped graphs.
"""
from cmk.graphing.v1 import graphs, metrics, Title

UNIT_BYTES = metrics.Unit(metrics.IECNotation("B"))
UNIT_COUNT = metrics.Unit(metrics.DecimalNotation(""))
UNIT_SECONDS = metrics.Unit(metrics.TimeNotation())

metric_pbs_removed_bytes = metrics.Metric(
    name="removed_bytes",
    title=Title("Reclaimed in last garbage collection"),
    unit=UNIT_BYTES,
    color=metrics.Color.GREEN,
)

metric_pbs_disk_bytes = metrics.Metric(
    name="disk_bytes",
    title=Title("On-disk chunk store size"),
    unit=UNIT_BYTES,
    color=metrics.Color.BLUE,
)

metric_pbs_removed_bad_chunks = metrics.Metric(
    name="removed_bad_chunks",
    title=Title("Removed bad chunks"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)

metric_pbs_still_bad_chunks = metrics.Metric(
    name="still_bad_chunks",
    title=Title("Still-bad chunks"),
    unit=UNIT_COUNT,
    color=metrics.Color.RED,
)

metric_pbs_last_age = metrics.Metric(
    name="last_age",
    title=Title("Time since last run"),
    unit=UNIT_SECONDS,
    color=metrics.Color.CYAN,
)

graph_pbs_gc_bad_chunks = graphs.Graph(
    name="pbs_gc_bad_chunks",
    title=Title("PBS garbage collection: bad chunks"),
    simple_lines=[
        "removed_bad_chunks",
        "still_bad_chunks",
    ],
)
