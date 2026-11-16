#!/usr/bin/env python3
"""Graphing for OPNsense WireGuard and package audit checks.

Gateway (rta, pl), temperature (temp), WireGuard traffic (if_in_octets,
if_out_octets) and DHCP (used_dhcp_leases, free_dhcp_leases) reuse the
canonical Checkmk metrics defined centrally.
"""
from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, TimeNotation, Unit

metric_opnsense_wg_handshake_age = Metric(
    name="opnsense_wg_handshake_age",
    title=Title("Age of latest WireGuard handshake"),
    unit=Unit(TimeNotation()),
    color=Color.BLUE,
)

metric_opnsense_vulnerable_packages = Metric(
    name="opnsense_vulnerable_packages",
    title=Title("Vulnerable packages"),
    unit=Unit(DecimalNotation("")),
    color=Color.RED,
)
