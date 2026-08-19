#!/usr/bin/env python3
"""Graphing (metric colors/units, perfometers, graphs) for PMG checks."""
from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import (
    Color,
    DecimalNotation,
    Metric,
    Unit,
    IECNotation,
    SINotation,
    TimeNotation,
)
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import WarningOf, CriticalOf
from cmk.graphing.v1.perfometers import Perfometer, FocusRange, Closed, Open

UNIT_COUNT = Unit(DecimalNotation(""))
UNIT_PERCENT = Unit(DecimalNotation("%"))
UNIT_SECONDS = Unit(TimeNotation())
UNIT_BYTES_MB = Unit(SINotation("MB"))

metric_mail_count_in = Metric(
    name="mail_count_in",
    title=Title("Mails received"),
    unit=UNIT_COUNT,
    color=Color.BLUE,
)
metric_mail_count_out = Metric(
    name="mail_count_out",
    title=Title("Mails sent"),
    unit=UNIT_COUNT,
    color=Color.GREEN,
)
metric_mail_count = Metric(
    name="mail_count",
    title=Title("Total mail count"),
    unit=UNIT_COUNT,
    color=Color.PURPLE,
)
metric_mail_junk_percent = Metric(
    name="mail_junk_percent",
    title=Title("Junk ratio (PMG-reported)"),
    unit=UNIT_PERCENT,
    color=Color.BLUE,
)
metric_mail_spam_percent = Metric(
    name="mail_spam_percent",
    title=Title("Spam ratio"),
    unit=UNIT_PERCENT,
    color=Color.GREEN,
)
metric_mail_virus_percent = Metric(
    name="mail_virus_percent",
    title=Title("Virus ratio"),
    unit=UNIT_PERCENT,
    color=Color.PURPLE,
)
metric_mail_avptime = Metric(
    name="mail_avptime",
    title=Title("Average mail processing time"),
    unit=UNIT_SECONDS,
    color=Color.CYAN,
)
metric_pmg_rbl_rejects = Metric(
    name="pmg_rbl_rejects",
    title=Title("RBL rejects"),
    unit=UNIT_COUNT,
    color=Color.DARK_RED,
)
metric_pmg_pregreet_rejects = Metric(
    name="pmg_pregreet_rejects",
    title=Title("PREGREET rejects"),
    unit=UNIT_COUNT,
    color=Color.DARK_ORANGE,
)
metric_pmg_rejects_total = Metric(
    name="pmg_rejects_total",
    title=Title("Total SMTP rejects"),
    unit=UNIT_COUNT,
    color=Color.RED,
)
metric_mail_queue_length = Metric(
    name="mail_queue_length",
    title=Title("Mail queue length"),
    unit=UNIT_COUNT,
    color=Color.ORANGE,
)
metric_pmg_quarantine_count = Metric(
    name="pmg_quarantine_count",
    title=Title("Quarantined mails"),
    unit=UNIT_COUNT,
    color=Color.PURPLE,
)
metric_pmg_quarantine_mbytes = Metric(
    name="pmg_quarantine_mbytes",
    title=Title("Quarantine size"),
    unit=UNIT_BYTES_MB,
    color=Color.BLUE,
)
metric_pmg_quarantine_avgspam = Metric(
    name="pmg_quarantine_avgspam",
    title=Title("Average spam level"),
    unit=UNIT_COUNT,
    color=Color.YELLOW,
)
metric_pmg_clamav_nsigs = Metric(
    name="pmg_clamav_nsigs",
    title=Title("ClamAV signatures"),
    unit=UNIT_COUNT,
    color=Color.GREEN,
)
metric_pmg_clamav_age = Metric(
    name="pmg_clamav_age",
    title=Title("ClamAV database age"),
    unit=UNIT_SECONDS,
    color=Color.ORANGE,
)
metric_pmg_updates_pending = Metric(
    name="pmg_updates_pending",
    title=Title("Pending package updates"),
    unit=UNIT_COUNT,
    color=Color.ORANGE,
)
metric_pmg_cert_remaining = Metric(
    name="pmg_cert_remaining",
    title=Title("Certificate remaining validity"),
    unit=UNIT_SECONDS,
    color=Color.CYAN,
)

graph_pmg_mail_counts = Graph(
    name="pmg_mail_counts",
    title=Title("PMG mail throughput"),
    minimal_range=MinimalRange(0, 100),
    compound_lines=["mail_count_in", "mail_count_out"],
)

graph_pmg_junk_ratio = Graph(
    name="pmg_junk_ratio",
    title=Title("PMG junk/spam/virus ratio"),
    minimal_range=MinimalRange(0, 100),
    simple_lines=[
        "mail_spam_percent",
        "mail_virus_percent",
        "mail_junk_percent",
        WarningOf("mail_junk_percent"),
        CriticalOf("mail_junk_percent"),
    ],
)

perfometer_mail_queue_length = Perfometer(
    name="mail_queue_length",
    focus_range=FocusRange(Closed(0), Open(1000)),
    segments=["mail_queue_length"],
)

perfometer_mail_junk_percent = Perfometer(
    name="mail_junk_percent",
    focus_range=FocusRange(Closed(0), Closed(100)),
    segments=["mail_junk_percent"],
)
