#!/usr/bin/env python3
"""Graphing for the XenServer / XCP-ng checks.

Host/VM/SR checks reuse Checkmk's builtin metrics (util, load1, mem_used,
mem_used_percent, mem_total, if_in_bps, if_out_bps, disk_*_throughput,
disk_*_ios, disk_*_latency, disk_queue_length, power, uptime, time_offset,
fs_*). Those must not be redefined here.
"""
from cmk.graphing.v1 import Title, metrics, perfometers

UNIT_COUNT = metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(0))
UNIT_SECONDS = metrics.Unit(metrics.TimeNotation())

metric_xenserver_vms_running = metrics.Metric(
    name="xenserver_vms_running",
    title=Title("Running VMs"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)

metric_xenserver_snapshot_count = metrics.Metric(
    name="xenserver_snapshot_count",
    title=Title("Number of snapshots"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)

metric_xenserver_snapshot_age = metrics.Metric(
    name="xenserver_snapshot_age",
    title=Title("Age of the oldest snapshot"),
    unit=UNIT_SECONDS,
    color=metrics.Color.PURPLE,
)

perfometer_xenserver_snapshot_age = perfometers.Perfometer(
    name="xenserver_snapshot_age",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(30 * 86400)),
    segments=["xenserver_snapshot_age"],
)
