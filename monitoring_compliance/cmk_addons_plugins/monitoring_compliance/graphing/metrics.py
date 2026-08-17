#!/usr/bin/env python3
# Metric + perf-o-meter for the compliance value (Graphing API v1).

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import (
    Color,
    DecimalNotation,
    Metric,
    StrictPrecision,
    Unit,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Perfometer

_UNIT_PERCENT = Unit(DecimalNotation("%"), StrictPrecision(0))

metric_compliance_percent = Metric(
    name="compliance_percent",
    title=Title("Monitoring compliance"),
    unit=_UNIT_PERCENT,
    color=Color.GREEN,
)

perfometer_compliance_percent = Perfometer(
    name="compliance_percent",
    focus_range=FocusRange(Closed(0), Closed(100)),
    segments=["compliance_percent"],
)

_UNIT_COUNT = Unit(DecimalNotation(""), StrictPrecision(0))
_UNIT_BYTES = Unit(DecimalNotation("B"), StrictPrecision(0))

metric_capability_db_entries = Metric(
    name="capability_db_entries",
    title=Title("Capability database entries"),
    unit=_UNIT_COUNT,
    color=Color.BLUE,
)

metric_capability_db_size = Metric(
    name="capability_db_size",
    title=Title("Capability database size"),
    unit=_UNIT_BYTES,
    color=Color.GRAY,
)

metric_capability_db_monitorable = Metric(
    name="capability_db_monitorable",
    title=Title("Monitorable capabilities"),
    unit=_UNIT_COUNT,
    color=Color.CYAN,
)

metric_capability_db_monitored = Metric(
    name="capability_db_monitored",
    title=Title("Monitored capabilities"),
    unit=_UNIT_COUNT,
    color=Color.GREEN,
)

metric_capability_db_hosts = Metric(
    name="capability_db_hosts",
    title=Title("Hosts contributing capabilities"),
    unit=_UNIT_COUNT,
    color=Color.ORANGE,
)

metric_known_catalog_total = Metric(
    name="known_catalog_total",
    title=Title("Known application types"),
    unit=_UNIT_COUNT,
    color=Color.PURPLE,
)

metric_known_catalog_available = Metric(
    name="known_catalog_available",
    title=Title("Known types monitorable on this site"),
    unit=_UNIT_COUNT,
    color=Color.GREEN,
)
