#!/usr/bin/env python3
"""OPNsense WireGuard peers - one service per peer.

Source: wireguard/service/show, "rows" contains one entry per interface
(type "interface") and per peer (type "peer"), e.g.
    {"if": "wg0", "type": "peer", "name": "site-b", "public-key": "...",
     "endpoint": "198.51.100.7:51820", "allowed-ips": "10.0.0.2/32",
     "latest-handshake": 1794823329, "transfer-rx": 1234, "transfer-tx": 567,
     "ifname": "WG_VPN", "peer-status": "online"}
"""
import json
import time

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    GetRateError,
    Metric,
    Result,
    Service,
    State,
    check_levels,
    get_rate,
    get_value_store,
    render,
)


def _peer_item(row):
    name = row.get("name") or (row.get("public-key") or "")[:8]
    iface = row.get("if") or row.get("interface") or ""
    return "%s %s" % (iface, name) if iface else str(name)


def parse_opnsense_wireguard(string_table):
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
    rows = data.get("rows")
    if not isinstance(rows, list):
        return {}
    peers = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != "peer":
            continue
        item = _peer_item(row)
        if item:
            peers[item] = row
    return {"peers": peers}


agent_section_opnsense_wireguard = AgentSection(
    name="opnsense_wireguard",
    parse_function=parse_opnsense_wireguard,
)


def _int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def discover_opnsense_wireguard(section):
    for item in sorted(section.get("peers", {})):
        yield Service(item=item)


def check_opnsense_wireguard(item, params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s (privilege 'VPN: WireGuard: Status'?)"
                     % section["_error"])
        return
    peer = section.get("peers", {}).get(item)
    if peer is None:
        yield Result(state=State(params.get("state_missing", 3)),
                     summary="Peer not found in API data (removed or disabled?)")
        return

    handshake = _int(peer.get("latest-handshake"))
    now = time.time()
    if not handshake:
        yield Result(state=State(params.get("state_no_handshake", 1)),
                     summary="No handshake yet")
    else:
        age = max(0.0, now - handshake)
        yield from check_levels(
            age,
            levels_upper=params.get("levels_handshake_age"),
            metric_name="opnsense_wg_handshake_age",
            render_func=render.timespan,
            label="Last handshake",
            boundaries=(0, None),
        )

    store = get_value_store()
    for key, metric, label in (("transfer-rx", "if_in_octets", "In"),
                               ("transfer-tx", "if_out_octets", "Out")):
        counter = _int(peer.get(key))
        if counter is None:
            continue
        try:
            rate = get_rate(store, "%s.%s" % (item, key), now, counter,
                            raise_overflow=True)
        except GetRateError:
            continue
        yield Result(state=State.OK, summary="%s: %s" % (label, render.iobandwidth(rate)))
        yield Metric(metric, rate, boundaries=(0, None))

    details = []
    for key, label in (("endpoint", "Endpoint"), ("allowed-ips", "Allowed IPs"),
                       ("ifname", "Interface"), ("public-key", "Public key")):
        if peer.get(key):
            details.append("%s: %s" % (label, peer[key]))
    if details:
        yield Result(state=State.OK, notice="; ".join(details))


check_plugin_opnsense_wireguard = CheckPlugin(
    name="opnsense_wireguard",
    sections=["opnsense_wireguard"],
    service_name="OPNsense WireGuard %s",
    discovery_function=discover_opnsense_wireguard,
    check_function=check_opnsense_wireguard,
    check_default_parameters={
        "levels_handshake_age": ("fixed", (300.0, 900.0)),
        "state_no_handshake": 1,
        "state_missing": 3,
    },
    check_ruleset_name="opnsense_wireguard",
)
