#!/usr/bin/env python3
"""Graphing for the OPNsense special agent.

All metrics emitted by the OPNsense checks intentionally reuse Checkmk's
canonical metric names (load1/load5/load15, mem_used, mem_used_percent,
swap_used, fs_used_percent, uptime). Those metrics already carry builtin
definitions (title, unit, colour) and builtin graphs/perfometers, so we do
NOT redefine them here (that would raise a duplicate-registration error and
break plugin loading).

What we add are OPNsense-specific *combined* graphs with unique names that
reference the existing metrics, giving a single grouped view on the
OPNsense System and OPNsense Memory services.
"""
from cmk.graphing.v1 import graphs, Title

# Grouped load-average graph for the "OPNsense System" service.
graph_opnsense_loadavg = graphs.Graph(
    name="opnsense_loadavg",
    title=Title("OPNsense load average"),
    simple_lines=[
        "load1",
        "load5",
        "load15",
    ],
)

# Grouped RAM + swap graph for the "OPNsense Memory" service.
graph_opnsense_memory = graphs.Graph(
    name="opnsense_memory",
    title=Title("OPNsense memory and swap usage"),
    compound_lines=[
        "mem_used",
    ],
    simple_lines=[
        "swap_used",
    ],
)
