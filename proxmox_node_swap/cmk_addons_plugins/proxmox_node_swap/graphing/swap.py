#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Graphing plug-in for the "Proxmox Node Swap Usage" check.
#
# IMPORTANT: metric names are GLOBAL across all of Checkmk. Since Checkmk 2.5,
# `swap_used_percent` is a built-in metric (cmk.plugins.collection.graphing.
# standalone). Defining it again here raises
#     plug-in 'swap_used_percent' already defined at ...
# which stops the whole graphing module from loading. So we do NOT redefine it;
# we only add a perf-o-meter that references it. `swap_used_bytes` is not a
# built-in, so we define that one to get proper byte (IEC) formatting.
#
# Requires the cmk.graphing.v1 API -> Checkmk 2.3.0 or newer.

from cmk.graphing.v1 import Title, metrics, perfometers

metric_swap_used_bytes = metrics.Metric(
    name="swap_used_bytes",
    title=Title("Swap used (absolute)"),
    unit=metrics.Unit(metrics.IECNotation("B")),
    color=metrics.Color.ORANGE,
)

# Perf-o-meter: a 0-100 % bar filled by the node swap-used percentage.
# `swap_used_percent` comes from Checkmk's built-in metric catalogue; the
# check's perfdata provides the value.
perfometer_proxmox_node_swap = perfometers.Perfometer(
    name="proxmox_node_swap",
    focus_range=perfometers.FocusRange(
        perfometers.Closed(0),
        perfometers.Closed(100),
    ),
    segments=["swap_used_percent"],
)
