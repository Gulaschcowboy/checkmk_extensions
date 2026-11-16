#!/usr/bin/env python3
"""OPNsense DHCPv4 pool usage (Kea and Dnsmasq) - one service per pool.

The agent emits the configured ranges plus the addresses of active leases:
    {"kea": {"subnets": [{"subnet": "192.168.1.0/24",
                          "pools": "192.168.1.100-192.168.1.199",
                          "description": "LAN"}],
             "leases": [{"address": "192.168.1.101", "state": "0"}]},
     "dnsmasq": {"ranges": [{"interface": "lan", "start_addr": "...",
                             "end_addr": "...", "description": ""}],
                 "leases": [{"address": "..."}]}}

Used = active leases whose address lies inside the pool. Static
reservations outside the pool are not counted.
"""
import ipaddress
import json
import re

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    check_levels,
)


def parse_opnsense_dhcp(string_table):
    if not string_table:
        return {}
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}
    return data if isinstance(data, dict) else {}


agent_section_opnsense_dhcp = AgentSection(
    name="opnsense_dhcp",
    parse_function=parse_opnsense_dhcp,
)


def _range(spec):
    """'a.b.c.d-e.f.g.h' or 'a.b.c.d/nn' -> (first_int, last_int) or None."""
    spec = spec.strip()
    try:
        if "-" in spec:
            start, end = (s.strip() for s in spec.split("-", 1))
            lo = int(ipaddress.IPv4Address(start))
            hi = int(ipaddress.IPv4Address(end))
            return (lo, hi) if lo <= hi else (hi, lo)
        if "/" in spec:
            net = ipaddress.IPv4Network(spec, strict=False)
            hosts = list(net.hosts()) if net.num_addresses <= 2 else None
            if hosts is not None:
                return (int(hosts[0]), int(hosts[-1])) if hosts else None
            return (int(net.network_address) + 1, int(net.broadcast_address) - 1)
    except ValueError:
        return None
    return None


def _list(value):
    """Accept a plain list or a raw OPNsense search payload ({"rows": [...]})."""
    if isinstance(value, dict):
        value = value.get("rows")
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _pools(section):
    """Return {item: {"ranges": [(lo, hi)], "leases": [addr_int], ...}}."""
    pools = {}

    kea = section.get("kea") or {}
    kea_leases = []
    for lease in _list(kea.get("leases")):
        # Kea lease states: 0 default (active), 1 declined, 2 expired-reclaimed
        if str(lease.get("state", "0")) != "0":
            continue
        try:
            kea_leases.append(int(ipaddress.IPv4Address(lease.get("address", ""))))
        except ValueError:
            continue
    for subnet in _list(kea.get("subnets")):
        ranges = [r for r in (_range(p) for p in
                              re.split(r"[\s,]+", subnet.get("pools") or ""))
                  if r]
        if not ranges or not subnet.get("subnet"):
            continue
        pools["Kea %s" % subnet["subnet"]] = {
            "ranges": ranges,
            "leases": kea_leases,
            "description": subnet.get("description", ""),
            "error": kea.get("leases_error"),
        }

    dnsmasq = section.get("dnsmasq") or {}
    dm_leases = []
    for lease in _list(dnsmasq.get("leases")):
        try:
            dm_leases.append(int(ipaddress.IPv4Address(lease.get("address", ""))))
        except ValueError:
            continue
    for rng in _list(dnsmasq.get("ranges")):
        start, end = rng.get("start_addr", ""), rng.get("end_addr", "")
        r = _range("%s-%s" % (start, end)) if start and end else None
        if not r:
            continue  # IPv6 / constructor ranges are not supported
        pools["Dnsmasq %s-%s" % (start, end)] = {
            "ranges": [r],
            "leases": dm_leases,
            "description": rng.get("description") or rng.get("interface", ""),
            "error": dnsmasq.get("leases_error"),
        }
    return pools


def discover_opnsense_dhcp(section):
    for item in sorted(_pools(section)):
        yield Service(item=item)


def check_opnsense_dhcp(item, params, section):
    backend = item.split(" ", 1)[0].lower()
    sub = section.get(backend) or {}
    if "_error" in sub:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % sub["_error"])
        return
    pool = _pools(section).get(item)
    if pool is None:
        yield Result(state=State.UNKNOWN, summary="Pool not found in API data")
        return
    if pool["error"]:
        yield Result(state=State.UNKNOWN,
                     summary="Cannot read leases: %s" % pool["error"])
        return

    size = sum(hi - lo + 1 for lo, hi in pool["ranges"])
    used = len({a for a in pool["leases"]
                if any(lo <= a <= hi for lo, hi in pool["ranges"])})
    free = max(0, size - used)
    pct = 100.0 * used / size if size else 0.0

    yield from check_levels(
        pct,
        levels_upper=params.get("levels_used"),
        render_func=lambda v: "%.1f%%" % v,
        label="Used",
    )
    yield Result(state=State.OK,
                 summary="%d of %d leases in use, %d free" % (used, size, free))
    yield Metric("used_dhcp_leases", used, boundaries=(0, size))
    yield Metric("free_dhcp_leases", free, boundaries=(0, size))
    if pool["description"]:
        yield Result(state=State.OK, notice="Description: %s" % pool["description"])


check_plugin_opnsense_dhcp = CheckPlugin(
    name="opnsense_dhcp",
    sections=["opnsense_dhcp"],
    service_name="OPNsense DHCP Pool %s",
    discovery_function=discover_opnsense_dhcp,
    check_function=check_opnsense_dhcp,
    check_default_parameters={"levels_used": ("fixed", (80.0, 90.0))},
    check_ruleset_name="opnsense_dhcp",
)
