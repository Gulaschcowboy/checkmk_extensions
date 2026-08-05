#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Metric definitions for the mail_domain_health check plugins."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, StrictPrecision, Unit
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

_COUNT = Unit(DecimalNotation(""), StrictPrecision(0))

metric_rbl_listings = Metric(
    name="rbl_listings",
    title=Title("Blacklist listings"),
    unit=_COUNT,
    color=Color.RED,
)

metric_rbl_query_errors = Metric(
    name="rbl_query_errors",
    title=Title("Failed DNSBL queries"),
    unit=_COUNT,
    color=Color.ORANGE,
)

metric_spf_dns_lookups = Metric(
    name="spf_dns_lookups",
    title=Title("SPF DNS lookups"),
    unit=_COUNT,
    color=Color.BLUE,
)

metric_domain_bl_listings = Metric(
    name="domain_bl_listings",
    title=Title("Domain blacklist listings"),
    unit=_COUNT,
    color=Color.RED,
)

metric_domain_bl_query_errors = Metric(
    name="domain_bl_query_errors",
    title=Title("Failed domain blacklist queries"),
    unit=_COUNT,
    color=Color.ORANGE,
)

_DAYS = Unit(DecimalNotation("d"), StrictPrecision(0))

metric_domain_expiry_days = Metric(
    name="domain_expiry_days",
    title=Title("Days until domain registration expires"),
    unit=_DAYS,
    color=Color.GREEN,
)

# RBL: the meter tracks the number of blacklist listings. An empty bar means
# all lists are clean (consistent with the "N/N lists clean" summary); the bar
# fills as listings appear. The upper bound is open because there is no fixed
# maximum - it simply grows with the number of configured lists.
perfometer_mail_domain_health_rbl = Perfometer(
    name="mail_domain_health_rbl",
    focus_range=FocusRange(Closed(0), Open(5)),
    segments=["rbl_listings"],
)

# SPF: the meter fills from 0 towards the RFC 7208 hard limit of 10 DNS lookups.
# A nearly full bar is an early warning that the record is close to breaking.
perfometer_mail_domain_health_spf = Perfometer(
    name="mail_domain_health_spf",
    focus_range=FocusRange(Closed(0), Closed(10)),
    segments=["spf_dns_lookups"],
)

# Domain blacklist: same idea as the RBL meter - empty bar means all clean.
perfometer_mail_domain_health_domain_bl = Perfometer(
    name="mail_domain_health_domain_bl",
    focus_range=FocusRange(Closed(0), Open(3)),
    segments=["domain_bl_listings"],
)

# Domain expiry: full bar = plenty of time (>= 90 days), draining as expiry nears.
perfometer_mail_domain_health_rdap = Perfometer(
    name="mail_domain_health_rdap",
    focus_range=FocusRange(Closed(0), Closed(90)),
    segments=["domain_expiry_days"],
)
