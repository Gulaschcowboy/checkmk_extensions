#!/usr/bin/env python3
"""OPNsense gateway status (dpinger) - one service per gateway.

Source: routes/gateway/status, e.g.
    {"items": [{"name": "WAN_DHCP", "address": "203.0.113.1",
                "status": "none", "status_translated": "Online",
                "loss": "0.0 %", "stddev": "0.2 ms", "delay": "1.3 ms",
                "monitor": "203.0.113.1"}], "status": "ok"}

"status" is dpinger's verdict: none (online), loss, delay, delay+loss,
down, force_down. Gateways without monitoring report "~" for the values.
"""
import json
import re

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Result,
    Service,
    State,
    check_levels,
)


def parse_opnsense_gateways(string_table):
    if not string_table:
        return {}
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}
    if not isinstance(data, dict):
        return {}
    if "_error" in data:
        return {"_error": data["_error"]}
    items = data.get("items")
    if not isinstance(items, list):
        return {}
    return {
        "gateways": {
            str(gw.get("name")): gw
            for gw in items
            if isinstance(gw, dict) and gw.get("name")
        }
    }


agent_section_opnsense_gateways = AgentSection(
    name="opnsense_gateways",
    parse_function=parse_opnsense_gateways,
)


def _number(value):
    """'1.3 ms' -> 1.3, '0.0 %' -> 0.0, '~' / '' / None -> None."""
    if isinstance(value, (int, float)):
        return float(value)
    m = re.search(r"-?\d+(?:\.\d+)?", str(value or ""))
    return float(m.group(0)) if m else None


def discover_opnsense_gateways(section):
    for name in sorted(section.get("gateways", {})):
        yield Service(item=name)


_STATUS_TEXT = {
    "none": "Online",
    "loss": "Packet loss",
    "delay": "High latency",
    "delay+loss": "High latency and packet loss",
    "down": "Offline",
    "force_down": "Offline (forced)",
}


def check_opnsense_gateways(item, params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s (privilege 'System: Gateways'?)"
                     % section["_error"])
        return
    gw = section.get("gateways", {}).get(item)
    if gw is None:
        yield Result(state=State(params.get("state_missing", 3)),
                     summary="Gateway not found in API data")
        return

    status = str(gw.get("status") or "none")
    text = gw.get("status_translated") or _STATUS_TEXT.get(status, status)
    state_key = "state_%s" % status.replace("+", "_")
    default = {"none": 0, "down": 2}.get(status, 1)
    yield Result(state=State(params.get(state_key, default)),
                 summary="Status: %s" % text)

    delay = _number(gw.get("delay"))
    if delay is not None:
        # dpinger reports milliseconds; Checkmk's canonical "rta" is seconds.
        levels = params.get("levels_rtt")
        if levels and levels[0] == "fixed":
            levels = ("fixed", (levels[1][0] / 1000.0, levels[1][1] / 1000.0))
        result, metric = check_levels(
            delay / 1000.0,
            levels_upper=levels,
            metric_name="rta",
            render_func=lambda v: "%.1f ms" % (v * 1000.0),
            label="RTT",
            boundaries=(0, None),
        )
        yield result
        yield metric

    loss = _number(gw.get("loss"))
    if loss is not None:
        result, metric = check_levels(
            loss,
            levels_upper=params.get("levels_loss"),
            metric_name="pl",
            render_func=lambda v: "%.1f%%" % v,
            label="Packet loss",
            boundaries=(0, 100),
        )
        yield result
        yield metric

    stddev = _number(gw.get("stddev"))
    details = []
    if stddev is not None:
        details.append("RTT std. deviation: %.1f ms" % stddev)
    if gw.get("address"):
        details.append("Gateway address: %s" % gw["address"])
    if gw.get("monitor") and gw.get("monitor") != gw.get("address"):
        details.append("Monitor IP: %s" % gw["monitor"])
    if delay is None and loss is None:
        details.append("Gateway monitoring disabled - no RTT/loss data")
    if details:
        yield Result(state=State.OK, notice="; ".join(details))


check_plugin_opnsense_gateways = CheckPlugin(
    name="opnsense_gateways",
    sections=["opnsense_gateways"],
    service_name="OPNsense Gateway %s",
    discovery_function=discover_opnsense_gateways,
    check_function=check_opnsense_gateways,
    check_default_parameters={
        "state_loss": 1,
        "state_delay": 1,
        "state_delay_loss": 1,
        "state_down": 2,
        "state_force_down": 1,
        "state_missing": 3,
        "levels_rtt": ("no_levels", None),
        "levels_loss": ("no_levels", None),
    },
    check_ruleset_name="opnsense_gateways",
)
