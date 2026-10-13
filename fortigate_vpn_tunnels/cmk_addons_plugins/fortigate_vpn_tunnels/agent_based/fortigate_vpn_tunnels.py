#!/usr/bin/env python3
"""FortiGate IPsec VPN: one service per phase 2 tunnel.

Checkmk's built-in "fortigate_ipsecvpn" check only reports a summary of all
tunnels ("Total: 22, Up: 9, Down: 13"). This plugin reads the same table
(FORTINET-FORTIGATE-MIB::fgVpnTunTable) and creates one service per phase 2
selector, so every tunnel has its own state, history and notifications.

fgVpnTunTable columns used (.1.3.6.1.4.1.12356.101.12.2.2.1.<col>):
     2 fgVpnTunEntPhase1Name
     3 fgVpnTunEntPhase2Name
     4 fgVpnTunEntRemGwyIp
     6 fgVpnTunEntLocGwyIp
     8 fgVpnTunEntSelectorSrcBeginIp
     9 fgVpnTunEntSelectorSrcEndIp
    11 fgVpnTunEntSelectorDstBeginIp
    12 fgVpnTunEntSelectorDstEndIp
    15 fgVpnTunEntLifeSecs
    17 fgVpnTunEntTimeout      (seconds until the SA expires)
    18 fgVpnTunEntInOctets     (FortiOS reports these per phase 1)
    19 fgVpnTunEntOutOctets
    20 fgVpnTunEntStatus       down(1), up(2)
    21 fgVpnTunEntVdom         index into fgVdTable
"""

import ipaddress
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    render,
    Service,
    SNMPSection,
    SNMPTree,
    startswith,
    State,
    StringTable,
)

DETECT_FORTIGATE = startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.12356.101.1.")


@dataclass(frozen=True)
class Tunnel:
    phase1: str
    phase2: str
    vdom: str
    remote_gateway: str
    local_gateway: str
    local_selector: str
    remote_selector: str
    up: bool
    lifetime: int | None
    timeout: int | None
    in_octets: int | None
    out_octets: int | None


Section = Mapping[str, Tunnel]


def _int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _selector(begin: str, end: str) -> str:
    """Render a selector address range compactly (CIDR where possible)."""
    if (begin, end) in (("0.0.0.0", "255.255.255.255"), ("", "")):
        return "any"
    try:
        first = ipaddress.ip_address(begin)
        last = ipaddress.ip_address(end)
        if first == last:
            return str(first)
        return ", ".join(
            str(net) for net in ipaddress.summarize_address_range(first, last)
        )
    except (ValueError, TypeError):
        return f"{begin}-{end}"


def parse_fortigate_vpn_tunnels(string_table: Sequence[StringTable]) -> Section:
    tunnel_rows, vdom_rows = string_table
    vdoms = {index: name for index, name in vdom_rows}

    tunnels: list[Tunnel] = []
    for (
        p1name,
        p2name,
        rem_gw,
        loc_gw,
        src_begin,
        src_end,
        dst_begin,
        dst_end,
        lifetime,
        timeout,
        in_octets,
        out_octets,
        status,
        vdom_index,
    ) in tunnel_rows:
        if not p2name:
            continue
        tunnels.append(
            Tunnel(
                phase1=p1name,
                phase2=p2name,
                vdom=vdoms.get(vdom_index, vdom_index),
                remote_gateway=rem_gw,
                local_gateway=loc_gw,
                local_selector=_selector(src_begin, src_end),
                remote_selector=_selector(dst_begin, dst_end),
                up=status == "2",
                lifetime=_int(lifetime),
                timeout=_int(timeout),
                in_octets=_int(in_octets),
                out_octets=_int(out_octets),
            )
        )

    # Phase 2 names are unique per VDOM. Only if the same name exists in
    # several VDOMs, the VDOM is added to the item to keep items unique.
    name_count = Counter(t.phase2 for t in tunnels)
    section: dict[str, Tunnel] = {}
    for tunnel in tunnels:
        item = tunnel.phase2
        if name_count[item] > 1:
            item = f"{item} (VDOM {tunnel.vdom})"
        section[item] = tunnel
    return section


snmp_section_fortigate_vpn_tunnels = SNMPSection(
    name="fortigate_vpn_tunnels",
    detect=DETECT_FORTIGATE,
    fetch=[
        SNMPTree(
            base=".1.3.6.1.4.1.12356.101.12.2.2.1",
            oids=["2", "3", "4", "6", "8", "9", "11", "12", "15", "17", "18", "19", "20", "21"],
        ),
        SNMPTree(
            base=".1.3.6.1.4.1.12356.101.3.2.1.1",
            oids=["1", "2"],  # fgVdEntIndex, fgVdEntName
        ),
    ],
    parse_function=parse_fortigate_vpn_tunnels,
)


def discover_fortigate_vpn_tunnel(params: Mapping[str, Any], section: Section) -> DiscoveryResult:
    discover_down = params.get("discover_down", True)
    for item, tunnel in section.items():
        if tunnel.up or discover_down:
            yield Service(item=item)


def check_fortigate_vpn_tunnel(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (tunnel := section.get(item)) is None:
        return

    if tunnel.up:
        yield Result(state=State.OK, summary="Status: up")
    else:
        yield Result(state=State(params.get("state_down", 2)), summary="Status: down")

    if tunnel.phase1 != tunnel.phase2:
        yield Result(state=State.OK, summary=f"Phase 1: {tunnel.phase1}")
    yield Result(state=State.OK, summary=f"Remote gateway: {tunnel.remote_gateway}")
    yield Result(
        state=State.OK,
        summary=f"Selectors: {tunnel.local_selector} <-> {tunnel.remote_selector}",
    )

    yield Result(state=State.OK, notice=f"VDOM: {tunnel.vdom}")
    yield Result(state=State.OK, notice=f"Local gateway: {tunnel.local_gateway}")
    if tunnel.up and tunnel.lifetime:
        yield Result(state=State.OK, notice=f"SA lifetime: {render.timespan(tunnel.lifetime)}")
    if tunnel.up and tunnel.timeout is not None:
        yield Result(
            state=State.OK, notice=f"SA expires in: {render.timespan(tunnel.timeout)}"
        )
    if tunnel.in_octets is not None and tunnel.out_octets is not None:
        yield Result(
            state=State.OK,
            notice=(
                f"Traffic of phase 1 {tunnel.phase1} (shared by all its selectors): "
                f"in {render.bytes(tunnel.in_octets)}, out {render.bytes(tunnel.out_octets)}"
            ),
        )


check_plugin_fortigate_vpn_tunnel = CheckPlugin(
    name="fortigate_vpn_tunnel",
    sections=["fortigate_vpn_tunnels"],
    service_name="VPN IPSec Tunnel %s",
    discovery_function=discover_fortigate_vpn_tunnel,
    discovery_ruleset_name="discovery_fortigate_vpn_tunnel",
    discovery_default_parameters={"discover_down": True},
    check_function=check_fortigate_vpn_tunnel,
    check_ruleset_name="fortigate_vpn_tunnel",
    check_default_parameters={"state_down": 2},
)
