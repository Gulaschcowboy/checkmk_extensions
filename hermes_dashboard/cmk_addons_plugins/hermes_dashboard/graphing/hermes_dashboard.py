#!/usr/bin/env python3
"""Graphing for the Hermes Agent dashboard checks."""
from cmk.graphing.v1 import metrics, Title

UNIT_COUNT = metrics.Unit(metrics.DecimalNotation(""))

metric_hermes_dashboard_active_sessions = metrics.Metric(
    name="active_sessions",
    title=Title("Active Hermes sessions"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
