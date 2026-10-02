#!/usr/bin/env python3
"""Graphing for OPNsense SMART disk health.

The temperature metric reuses the canonical Checkmk metric ``temp`` (defined
centrally). The SSD life remaining metric is plugin-specific and defined here.
"""
from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, Unit

UNIT_PERCENTAGE = Unit(DecimalNotation("%"))

metric_ssd_life_remaining = Metric(
    name="ssd_life_remaining",
    title=Title("SSD life remaining"),
    unit=UNIT_PERCENTAGE,
    color=Color.GREEN,
)

graph_opnsense_smart_life = Graph(
    name="opnsense_smart_life",
    title=Title("OPNsense SSD life remaining"),
    simple_lines=["ssd_life_remaining"],
)
