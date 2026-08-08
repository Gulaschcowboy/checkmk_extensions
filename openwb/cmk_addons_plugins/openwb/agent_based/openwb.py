#!/usr/bin/env python3
"""openWB checks: chargepoints, grid counters, batteries, PV inverters.

Data comes from the special agent {agent_openwb}, which auto-discovers
devices by probing the read-only openWB simpleAPI
(http://<host>/openWB/simpleAPI/simpleapi.php) — see
https://wiki.openwb.de/doku.php?id=openwb:vc:2.2.0:simpleapi
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def _fixed_levels(level_spec):
    """Unwrap a SimpleLevels value: ("fixed", (warn, crit)) -> (warn, crit),
    ("no_levels", None) -> (None, None). Also accepts a bare (warn, crit)
    tuple for backwards compatibility."""
    if isinstance(level_spec, tuple) and len(level_spec) == 2 and level_spec[0] in ("fixed", "no_levels"):
        kind, value = level_spec
        return value if kind == "fixed" else (None, None)
    return level_spec


def _parse_id_dict(string_table):
    if not string_table:
        return {}
    try:
        payload = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}
    if not isinstance(payload, dict) or "_error" in payload:
        return {}
    return payload


def _real_fault(entry):
    """The stub value from a non-existent device is the literal string
    "Kein Fehler" without quotes; a real device (even fault-free) reports
    a JSON-double-encoded string like '"Kein Fehler."'. Only surface a
    problem when the fault_state is nonzero or the text differs from the
    "no fault" wording."""
    fault_state = entry.get("fault_state", 0)
    fault_str = entry.get("fault_str") or ""
    text = fault_str.strip('"').rstrip(".")
    is_ok = fault_state in (0, "0") and text.lower() in ("kein fehler", "no error", "")
    return is_ok, text or "unknown"


# --------------------------------------------------------------------------
# Chargepoints
# --------------------------------------------------------------------------
def parse_openwb_chargepoint(string_table):
    return _parse_id_dict(string_table)


agent_section_openwb_chargepoint = AgentSection(
    name="openwb_chargepoint",
    parse_function=parse_openwb_chargepoint,
)


def discover_openwb_chargepoint(section):
    for cp_id in section:
        yield Service(item=cp_id)


def check_openwb_chargepoint(item, params, section):
    entry = section.get(item)
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary="No data for this chargepoint")
        return

    ok, fault_text = _real_fault(entry)
    yield Result(state=State.OK if ok else State.CRIT,
                 summary="No fault" if ok else "Fault: %s" % fault_text)

    plug_state = entry.get("plug_state")
    charge_state = entry.get("charge_state")
    if plug_state is not None:
        plug_txt = "connected" if plug_state else "not connected"
        charge_txt = ", charging" if charge_state else ", not charging" if plug_state else ""
        yield Result(state=State.OK, summary="Vehicle %s%s" % (plug_txt, charge_txt))

    vehicle_name = entry.get("connected_vehicle_name")
    if vehicle_name:
        yield Result(state=State.OK, summary="Vehicle: %s" % vehicle_name)

    chargemode = entry.get("chargemode")
    if chargemode:
        yield Result(state=State.OK, summary="Mode: %s" % chargemode)

    power = entry.get("power")
    if isinstance(power, (int, float)):
        warn, crit = _fixed_levels(params.get("power_levels", ("no_levels", None)))
        state = State.OK
        if crit is not None and power >= crit:
            state = State.CRIT
        elif warn is not None and power >= warn:
            state = State.WARN
        yield Result(state=state, summary="Power: %.0f W" % power)
        levels = (warn, crit) if warn is not None and crit is not None else None
        yield Metric("openwb_cp_power", power, levels=levels)

    soc = entry.get("soc")
    if isinstance(soc, (int, float)) and soc > 0:
        yield Result(state=State.OK, summary="SoC: %.0f%%" % soc)
        yield Metric("openwb_cp_soc", soc, boundaries=(0, 100))

    daily_imported = entry.get("daily_imported")
    if isinstance(daily_imported, (int, float)):
        yield Metric("openwb_cp_daily_imported", daily_imported / 1000.0)

    imported = entry.get("imported")
    if isinstance(imported, (int, float)):
        yield Result(state=State.OK, summary="Total charged: %.2f kWh" % (imported / 1000.0))
        yield Metric("openwb_cp_imported", imported / 1000.0)


check_plugin_openwb_chargepoint = CheckPlugin(
    name="openwb_chargepoint",
    service_name="openWB Chargepoint %s",
    discovery_function=discover_openwb_chargepoint,
    check_function=check_openwb_chargepoint,
    check_default_parameters={"power_levels": ("no_levels", None)},
    check_ruleset_name="openwb_chargepoint",
)


# --------------------------------------------------------------------------
# Grid counters
# --------------------------------------------------------------------------
def parse_openwb_counter(string_table):
    return _parse_id_dict(string_table)


agent_section_openwb_counter = AgentSection(
    name="openwb_counter",
    parse_function=parse_openwb_counter,
)


def discover_openwb_counter(section):
    for counter_id in section:
        yield Service(item=counter_id)


def check_openwb_counter(item, params, section):
    entry = section.get(item)
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary="No data for this counter")
        return

    ok, fault_text = _real_fault(entry)
    yield Result(state=State.OK if ok else State.CRIT,
                 summary="No fault" if ok else "Fault: %s" % fault_text)

    power = entry.get("power")
    if isinstance(power, (int, float)):
        direction = "import" if power > 0 else "export" if power < 0 else "balanced"
        yield Result(state=State.OK, summary="Grid power: %.0f W (%s)" % (power, direction))
        warn, crit = _fixed_levels(params.get("import_power_levels", ("no_levels", None)))
        state = State.OK
        if crit is not None and power >= crit:
            state = State.CRIT
        elif warn is not None and power >= warn:
            state = State.WARN
        if state != State.OK:
            yield Result(state=state, summary="Grid import power too high")
        levels = (warn, crit) if warn is not None and crit is not None else None
        yield Metric("openwb_counter_power", power, levels=levels)

    frequency = entry.get("frequency")
    if isinstance(frequency, (int, float)):
        yield Metric("openwb_counter_frequency", frequency)

    daily_imported = entry.get("daily_imported")
    if isinstance(daily_imported, (int, float)):
        yield Metric("openwb_counter_daily_imported", daily_imported / 1000.0)

    daily_exported = entry.get("daily_exported")
    if isinstance(daily_exported, (int, float)):
        yield Metric("openwb_counter_daily_exported", daily_exported / 1000.0)


check_plugin_openwb_counter = CheckPlugin(
    name="openwb_counter",
    service_name="openWB Counter %s",
    discovery_function=discover_openwb_counter,
    check_function=check_openwb_counter,
    check_default_parameters={"import_power_levels": ("no_levels", None)},
    check_ruleset_name="openwb_counter",
)


# --------------------------------------------------------------------------
# Batteries
# --------------------------------------------------------------------------
def parse_openwb_battery(string_table):
    return _parse_id_dict(string_table)


agent_section_openwb_battery = AgentSection(
    name="openwb_battery",
    parse_function=parse_openwb_battery,
)


def discover_openwb_battery(section):
    for battery_id in section:
        yield Service(item=battery_id)


def check_openwb_battery(item, params, section):
    entry = section.get(item)
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary="No data for this battery")
        return

    ok, fault_text = _real_fault(entry)
    yield Result(state=State.OK if ok else State.CRIT,
                 summary="No fault" if ok else "Fault: %s" % fault_text)

    soc = entry.get("soc")
    if isinstance(soc, (int, float)):
        warn, crit = _fixed_levels(params.get("soc_levels", ("no_levels", None)))
        state = State.OK
        if crit is not None and soc <= crit:
            state = State.CRIT
        elif warn is not None and soc <= warn:
            state = State.WARN
        yield Result(state=state, summary="State of charge: %.0f%%" % soc)
        levels = (warn, crit) if warn is not None and crit is not None else None
        yield Metric("openwb_battery_soc", soc, levels=levels, boundaries=(0, 100))

    power = entry.get("power")
    if isinstance(power, (int, float)):
        direction = "charging" if power > 0 else "discharging" if power < 0 else "idle"
        yield Result(state=State.OK, summary="Power: %.0f W (%s)" % (power, direction))
        yield Metric("openwb_battery_power", power)

    daily_imported = entry.get("daily_imported")
    if isinstance(daily_imported, (int, float)):
        yield Metric("openwb_battery_daily_imported", daily_imported / 1000.0)

    daily_exported = entry.get("daily_exported")
    if isinstance(daily_exported, (int, float)):
        yield Metric("openwb_battery_daily_exported", daily_exported / 1000.0)


check_plugin_openwb_battery = CheckPlugin(
    name="openwb_battery",
    service_name="openWB Battery %s",
    discovery_function=discover_openwb_battery,
    check_function=check_openwb_battery,
    check_default_parameters={"soc_levels": ("no_levels", None)},
    check_ruleset_name="openwb_battery",
)


# --------------------------------------------------------------------------
# PV inverters
# --------------------------------------------------------------------------
def parse_openwb_pv(string_table):
    return _parse_id_dict(string_table)


agent_section_openwb_pv = AgentSection(
    name="openwb_pv",
    parse_function=parse_openwb_pv,
)


def discover_openwb_pv(section):
    for pv_id in section:
        yield Service(item=pv_id)


def check_openwb_pv(item, section):
    entry = section.get(item)
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary="No data for this PV inverter")
        return

    ok, fault_text = _real_fault(entry)
    yield Result(state=State.OK if ok else State.CRIT,
                 summary="No fault" if ok else "Fault: %s" % fault_text)

    power = entry.get("power")
    if isinstance(power, (int, float)):
        # openWB reports PV generation as a negative power value.
        generation = -power
        yield Result(state=State.OK, summary="Generating: %.0f W" % generation)
        yield Metric("openwb_pv_power", generation)

    daily_exported = entry.get("daily_exported")
    if isinstance(daily_exported, (int, float)):
        yield Result(state=State.OK, summary="Today: %.2f kWh" % (daily_exported / 1000.0))
        yield Metric("openwb_pv_daily_exported", daily_exported / 1000.0)

    monthly_exported = entry.get("monthly_exported")
    if isinstance(monthly_exported, (int, float)):
        yield Metric("openwb_pv_monthly_exported", monthly_exported / 1000.0)

    yearly_exported = entry.get("yearly_exported")
    if isinstance(yearly_exported, (int, float)):
        yield Metric("openwb_pv_yearly_exported", yearly_exported / 1000.0)


check_plugin_openwb_pv = CheckPlugin(
    name="openwb_pv",
    service_name="openWB PV %s",
    discovery_function=discover_openwb_pv,
    check_function=check_openwb_pv,
)
