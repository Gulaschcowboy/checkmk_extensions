#!/usr/bin/env python3
"""Graphing for the openWB special agent.

Metrics use plugin-local names (openwb_*), so titles/units/colors are
defined here.
"""
from cmk.graphing.v1 import metrics, graphs, Title

UNIT_WATT = metrics.Unit(metrics.DecimalNotation("W"))
UNIT_PERCENT = metrics.Unit(metrics.DecimalNotation("%"))
UNIT_KWH = metrics.Unit(metrics.DecimalNotation("kWh"))
UNIT_HERTZ = metrics.Unit(metrics.DecimalNotation("Hz"))

metric_openwb_cp_power = metrics.Metric(
    name="openwb_cp_power", title=Title("Chargepoint power"),
    unit=UNIT_WATT, color=metrics.Color.ORANGE,
)
metric_openwb_cp_soc = metrics.Metric(
    name="openwb_cp_soc", title=Title("Vehicle state of charge"),
    unit=UNIT_PERCENT, color=metrics.Color.GREEN,
)
metric_openwb_cp_imported = metrics.Metric(
    name="openwb_cp_imported", title=Title("Chargepoint total energy charged"),
    unit=UNIT_KWH, color=metrics.Color.DARK_ORANGE,
)
metric_openwb_cp_daily_imported = metrics.Metric(
    name="openwb_cp_daily_imported", title=Title("Chargepoint energy charged today"),
    unit=UNIT_KWH, color=metrics.Color.YELLOW,
)

metric_openwb_counter_power = metrics.Metric(
    name="openwb_counter_power", title=Title("Grid power"),
    unit=UNIT_WATT, color=metrics.Color.BLUE,
)
metric_openwb_counter_frequency = metrics.Metric(
    name="openwb_counter_frequency", title=Title("Grid frequency"),
    unit=UNIT_HERTZ, color=metrics.Color.PURPLE,
)
metric_openwb_counter_daily_imported = metrics.Metric(
    name="openwb_counter_daily_imported", title=Title("Grid energy imported today"),
    unit=UNIT_KWH, color=metrics.Color.DARK_BLUE,
)
metric_openwb_counter_daily_exported = metrics.Metric(
    name="openwb_counter_daily_exported", title=Title("Grid energy exported today"),
    unit=UNIT_KWH, color=metrics.Color.LIGHT_BLUE,
)

metric_openwb_battery_soc = metrics.Metric(
    name="openwb_battery_soc", title=Title("Battery state of charge"),
    unit=UNIT_PERCENT, color=metrics.Color.GREEN,
)
metric_openwb_battery_power = metrics.Metric(
    name="openwb_battery_power", title=Title("Battery power"),
    unit=UNIT_WATT, color=metrics.Color.DARK_GREEN,
)
metric_openwb_battery_daily_imported = metrics.Metric(
    name="openwb_battery_daily_imported", title=Title("Battery energy charged today"),
    unit=UNIT_KWH, color=metrics.Color.CYAN,
)
metric_openwb_battery_daily_exported = metrics.Metric(
    name="openwb_battery_daily_exported", title=Title("Battery energy discharged today"),
    unit=UNIT_KWH, color=metrics.Color.DARK_CYAN,
)

metric_openwb_pv_power = metrics.Metric(
    name="openwb_pv_power", title=Title("PV generation power"),
    unit=UNIT_WATT, color=metrics.Color.YELLOW,
)
metric_openwb_pv_daily_exported = metrics.Metric(
    name="openwb_pv_daily_exported", title=Title("PV energy generated today"),
    unit=UNIT_KWH, color=metrics.Color.DARK_YELLOW,
)
metric_openwb_pv_monthly_exported = metrics.Metric(
    name="openwb_pv_monthly_exported", title=Title("PV energy generated this month"),
    unit=UNIT_KWH, color=metrics.Color.ORANGE,
)
metric_openwb_pv_yearly_exported = metrics.Metric(
    name="openwb_pv_yearly_exported", title=Title("PV energy generated this year"),
    unit=UNIT_KWH, color=metrics.Color.DARK_ORANGE,
)

graph_openwb_counter_energy = graphs.Graph(
    name="openwb_counter_energy",
    title=Title("openWB grid energy today"),
    simple_lines=["openwb_counter_daily_imported", "openwb_counter_daily_exported"],
)

graph_openwb_battery_energy = graphs.Graph(
    name="openwb_battery_energy",
    title=Title("openWB battery energy today"),
    simple_lines=["openwb_battery_daily_imported", "openwb_battery_daily_exported"],
)

graph_openwb_pv_yield = graphs.Graph(
    name="openwb_pv_yield",
    title=Title("openWB PV yield"),
    simple_lines=["openwb_pv_daily_exported", "openwb_pv_monthly_exported", "openwb_pv_yearly_exported"],
)
