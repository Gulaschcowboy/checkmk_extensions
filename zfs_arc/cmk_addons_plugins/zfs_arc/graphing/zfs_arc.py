#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Graphing plug-in for the "ZFS ARC cache usage" check.
#
# IMPORTANT: metric names are GLOBAL across all of Checkmk. Do NOT redeclare
# Checkmk builtins (power/current/energy/uptime/load1/mem_used, etc.) here --
# doing so raises "plug-in '<name>' already defined" and stops the whole
# graphing module from loading. All zfs_arc_* metric names below are
# plug-in-specific and safe to define.
#
# Requires the cmk.graphing.v1 API -> Checkmk 2.3.0 or newer.

from cmk.graphing.v1 import Title, graphs, metrics, perfometers

metric_zfs_arc_used_percent = metrics.Metric(
    name="zfs_arc_used_percent",
    title=Title("ARC size (percent of zfs_arc_max)"),
    unit=metrics.Unit(metrics.DecimalNotation("%")),
    color=metrics.Color.BLUE,
)

metric_zfs_arc_ram_percent = metrics.Metric(
    name="zfs_arc_ram_percent",
    title=Title("ARC size (percent of RAM)"),
    unit=metrics.Unit(metrics.DecimalNotation("%")),
    color=metrics.Color.ORANGE,
)

metric_zfs_arc_hit_ratio = metrics.Metric(
    name="zfs_arc_hit_ratio",
    title=Title("ARC hit ratio"),
    unit=metrics.Unit(metrics.DecimalNotation("%")),
    color=metrics.Color.GREEN,
)

metric_zfs_arc_size_bytes = metrics.Metric(
    name="zfs_arc_size_bytes",
    title=Title("ARC size (absolute)"),
    unit=metrics.Unit(metrics.IECNotation("B")),
    color=metrics.Color.PURPLE,
)

perfometer_zfs_arc = perfometers.Perfometer(
    name="zfs_arc",
    focus_range=perfometers.FocusRange(
        perfometers.Closed(0),
        perfometers.Closed(100),
    ),
    segments=["zfs_arc_ram_percent"],
)

graph_zfs_arc_usage = graphs.Graph(
    name="zfs_arc_usage",
    title=Title("ZFS ARC usage"),
    compound_lines=["zfs_arc_ram_percent"],
    simple_lines=["zfs_arc_used_percent", "zfs_arc_hit_ratio"],
)
