#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Metrics for the Commvault REST checks."""
from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, TimeNotation, Unit

_COUNT = Unit(DecimalNotation(""))
_TIME = Unit(TimeNotation())
_PERCENT = Unit(DecimalNotation("%"))

metric_commvault_rest_duration = Metric(
    name="commvault_rest_duration", title=Title("Agent run time"), unit=_TIME, color=Color.BLUE)
metric_commvault_rest_backup_age = Metric(
    name="commvault_rest_backup_age", title=Title("Age of last successful backup"), unit=_TIME, color=Color.ORANGE)
metric_commvault_rest_log_backup_age = Metric(
    name="commvault_rest_log_backup_age", title=Title("Age of last successful SQL transaction log backup"),
    unit=_TIME, color=Color.DARK_ORANGE)
metric_commvault_rest_active_jobs = Metric(
    name="commvault_rest_active_jobs", title=Title("Active jobs"), unit=_COUNT, color=Color.GREEN)
metric_commvault_rest_waiting_jobs = Metric(
    name="commvault_rest_waiting_jobs", title=Title("Waiting jobs"), unit=_COUNT, color=Color.YELLOW)
metric_commvault_rest_vms = Metric(
    name="commvault_rest_vms", title=Title("VMs"), unit=_COUNT, color=Color.BLUE)
metric_commvault_rest_vms_missed_sla = Metric(
    name="commvault_rest_vms_missed_sla", title=Title("VMs that missed the SLA"), unit=_COUNT, color=Color.RED)
metric_commvault_rest_license_remaining = Metric(
    name="commvault_rest_license_remaining", title=Title("License time remaining"), unit=_TIME, color=Color.PURPLE)
metric_commvault_rest_license_usage = Metric(
    name="commvault_rest_license_usage", title=Title("License usage"), unit=_PERCENT, color=Color.ORANGE)
metric_commvault_rest_license_used = Metric(
    name="commvault_rest_license_used", title=Title("License used"), unit=_COUNT, color=Color.BLUE)
metric_commvault_rest_license_total = Metric(
    name="commvault_rest_license_total", title=Title("License total"), unit=_COUNT, color=Color.GRAY)
