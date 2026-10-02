#!/usr/bin/env python3
"""OPNsense SMART disk health check.

One Checkmk service per physical disk detected by the OPNsense os-smart
plugin. Reports SMART self-assessment health, temperature and SSD life
remaining, with configurable thresholds.
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    render,
)


def parse_opnsense_smart(string_table: StringTable):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_opnsense_smart = AgentSection(
    name="opnsense_smart",
    parse_function=parse_opnsense_smart,
)


# ---------------------------------------------------------------------------
# Helpers to read smartctl --json=c fields defensively.
# ---------------------------------------------------------------------------
def _get_state(dev):
    state = dev.get("state")
    if isinstance(state, dict):
        return state
    return {}


def _model_serial(state):
    model = state.get("model_name", "Unknown model")
    serial = state.get("serial_number", "Unknown serial")
    return model, serial


def _health_passed(state):
    smart_status = state.get("smart_status")
    if isinstance(smart_status, dict):
        return smart_status.get("passed")
    return None


def _smartctl_errors(state):
    smartctl = state.get("smartctl")
    if not isinstance(smartctl, dict):
        return []
    messages = smartctl.get("messages")
    if not isinstance(messages, list):
        return []
    return [m.get("string", "") for m in messages if isinstance(m, dict)]


def _temperature(state):
    # ATA / SCSI style top-level temperature object.
    temp = state.get("temperature")
    if isinstance(temp, dict):
        current = temp.get("current")
        if isinstance(current, (int, float)):
            return float(current)
    # NVMe health log temperature (Celsius).
    nvme_log = state.get("nvme_smart_health_information_log")
    if isinstance(nvme_log, dict):
        current = nvme_log.get("temperature")
        if isinstance(current, (int, float)):
            return float(current)
    return None


def _power_on_hours(state):
    power_on = state.get("power_on_time")
    if isinstance(power_on, dict):
        hours = power_on.get("hours")
        if isinstance(hours, (int, float)):
            return int(hours)
    nvme_log = state.get("nvme_smart_health_information_log")
    if isinstance(nvme_log, dict):
        hours = nvme_log.get("power_on_hours")
        if isinstance(hours, (int, float)):
            return int(hours)
    return None


def _ata_attr(state, attr_id):
    table = state.get("ata_smart_attributes")
    if not isinstance(table, dict):
        return None
    for entry in table.get("table", []):
        if isinstance(entry, dict) and entry.get("id") == attr_id:
            return entry
    return None


def _ata_life_remaining(state):
    # Attribute 231 (SSD Life Left) is vendor-specific:
    # - Phison/PNY/Kingston A400: raw value = % life remaining (e.g. 68)
    # - Samsung: raw value = temperature, normalized value = % life remaining
    # We use the raw value when it looks like a percentage and does not match
    # the current disk temperature; otherwise we fall back to the normalized
    # value. Attribute 233 (Media Wearout Indicator) is the final fallback.
    temp = _temperature(state)
    attr = _ata_attr(state, 231)
    if attr is not None:
        raw = attr.get("raw")
        if isinstance(raw, dict):
            raw = raw.get("value")
        norm = attr.get("value")
        if isinstance(raw, (int, float)) and 0 <= raw <= 100:
            if temp is None or abs(raw - temp) > 5:
                return float(raw)
        if isinstance(norm, (int, float)) and 0 <= norm <= 100:
            return float(norm)

    attr = _ata_attr(state, 233)
    if attr is not None:
        value = attr.get("value")
        if isinstance(value, (int, float)) and 0 <= value <= 100:
            return float(value)
    return None


def _nvme_life_remaining(state):
    nvme_log = state.get("nvme_smart_health_information_log")
    if isinstance(nvme_log, dict):
        used = nvme_log.get("percentage_used")
        if isinstance(used, (int, float)):
            return max(0.0, 100.0 - float(used))
    return None


def _life_remaining(state):
    life = _nvme_life_remaining(state)
    if life is not None:
        return life
    return _ata_life_remaining(state)


# ---------------------------------------------------------------------------
# Discovery + check
# ---------------------------------------------------------------------------
def discover_opnsense_smart(section):
    if not section.get("installed"):
        return
    for dev in section.get("devices", []):
        item = dev.get("device")
        if item:
            yield Service(item=item)


def check_opnsense_smart(item, params, section):
    if not section or not section.get("installed"):
        yield Result(state=State.UNKNOWN, summary="No SMART data")
        return

    dev = None
    for d in section.get("devices", []):
        if d.get("device") == item:
            dev = d
            break
    if dev is None:
        yield Result(state=State.UNKNOWN,
                     summary="Disk not found in SMART data")
        return

    if dev.get("_error"):
        yield Result(state=State.UNKNOWN,
                     summary="SMART API error: %s" % dev["_error"])
        return

    state = _get_state(dev)
    if not state:
        yield Result(state=State.UNKNOWN,
                     summary="No SMART data for %s" % item)
        return

    model, serial = _model_serial(state)
    details_parts = []
    if model != "Unknown model":
        details_parts.append("Model: %s" % model)
    if serial != "Unknown serial":
        details_parts.append("Serial: %s" % serial)

    # --- Health self-assessment ---
    passed = _health_passed(state)
    if passed is False:
        failed_state = State(params.get("state_when_failed", 2))
        yield Result(state=failed_state, summary="Health: FAILED")
    elif passed is True:
        yield Result(state=State.OK, summary="Health: PASSED")
    else:
        errors = _smartctl_errors(state)
        if errors:
            yield Result(state=State.UNKNOWN,
                         summary="Health: unknown (%s)" % "; ".join(errors))
        else:
            yield Result(state=State.UNKNOWN, summary="Health: unknown")

    # --- Temperature ---
    temp = _temperature(state)
    if temp is not None:
        levels_upper = params.get("levels_temperature")
        result, metric = check_levels(
            temp,
            levels_upper=levels_upper,
            metric_name="temp",
            render_func=lambda v: "%.1f °C" % v,
            boundaries=(-273.15, None),
        )
        yield Result(state=result.state, summary="Temperature: %s" % result.summary)
        yield metric

    # --- SSD life remaining ---
    life = _life_remaining(state)
    if life is not None:
        levels_lower = params.get("levels_ssd_life")
        result, metric = check_levels(
            life,
            levels_lower=levels_lower,
            metric_name="ssd_life_remaining",
            render_func=lambda v: "%.0f%%" % v,
            boundaries=(0, 100),
        )
        yield Result(state=result.state,
                     summary="SSD life remaining: %s" % result.summary)
        yield metric

    # --- Power-on hours (informational) ---
    poh = _power_on_hours(state)
    if poh is not None:
        details_parts.append("Powered on: %s" % render.timespan(poh * 3600))

    if details_parts:
        yield Result(state=State.OK, notice="; ".join(details_parts))


check_plugin_opnsense_smart = CheckPlugin(
    name="opnsense_smart",
    sections=["opnsense_smart"],
    service_name="OPNsense SMART %s",
    discovery_function=discover_opnsense_smart,
    check_function=check_opnsense_smart,
    check_default_parameters={
        "state_when_failed": 2,
        "levels_temperature": ("fixed", (45.0, 55.0)),
        "levels_ssd_life": ("fixed", (50.0, 25.0)),
    },
    check_ruleset_name="opnsense_smart",
)
