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

UNIT_TOKENS = metrics.Unit(metrics.DecimalNotation(""))
UNIT_MONEY = metrics.Unit(metrics.DecimalNotation("$"))

metric_hermes_usage_cost = metrics.Metric(
    name="hermes_usage_cost",
    title=Title("Estimated usage cost"),
    unit=UNIT_MONEY,
    color=metrics.Color.ORANGE,
)

metric_hermes_usage_input_tokens = metrics.Metric(
    name="hermes_usage_input_tokens",
    title=Title("Input tokens"),
    unit=UNIT_TOKENS,
    color=metrics.Color.BLUE,
)

metric_hermes_usage_output_tokens = metrics.Metric(
    name="hermes_usage_output_tokens",
    title=Title("Output tokens"),
    unit=UNIT_TOKENS,
    color=metrics.Color.GREEN,
)

metric_hermes_usage_cache_read_tokens = metrics.Metric(
    name="hermes_usage_cache_read_tokens",
    title=Title("Cache-read tokens"),
    unit=UNIT_TOKENS,
    color=metrics.Color.CYAN,
)

metric_hermes_usage_sessions = metrics.Metric(
    name="hermes_usage_sessions",
    title=Title("Sessions in period"),
    unit=UNIT_COUNT,
    color=metrics.Color.PURPLE,
)

metric_hermes_usage_api_calls = metrics.Metric(
    name="hermes_usage_api_calls",
    title=Title("API calls in period"),
    unit=UNIT_COUNT,
    color=metrics.Color.YELLOW,
)
