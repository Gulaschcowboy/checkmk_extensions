#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Server-side check plug-in for the "proxmox_node_swap" agent section.
# ---------------------------------------------------------------------------
# Consumes the JSON emitted by the agent plug-in
# (cmk_addons_plugins/proxmox_node_swap/agents/proxmox_node_swap):
#
#   {"swap_total": <bytes>, "swap_used": <bytes>,
#    "guests": [{"type","id","name","swap","limit"}, ...]}
#
# and produces the service "Proxmox Node Swap Usage":
#   * state from a configurable percent-swap-used level (WATO ruleset)
#   * summary with the top-N swap-consuming guests
#   * details listing the top-M guests + accounting
#   * metrics: swap_used_percent, swap_used_bytes
# ---------------------------------------------------------------------------
import json

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    render,
)

TOP_SUMMARY = 2      # guests listed in the service summary
TOP_DETAILS = 10     # guests listed in the service details


def parse_proxmox_node_swap(string_table):
    if not string_table:
        return None
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None


agent_section_proxmox_node_swap = AgentSection(
    name="proxmox_node_swap",
    parse_function=parse_proxmox_node_swap,
)


def discover_proxmox_node_swap(section):
    if section is not None:
        yield Service()


def _guest_label(g):
    typ, gid, name = g["type"], g["id"], g["name"]
    sw, lim = g["swap"], g.get("limit")
    if lim:
        return "%s %s %s (%s, %.0f%%)" % (
            typ, gid, name, render.bytes(sw), sw / lim * 100.0)
    return "%s %s %s (%s)" % (typ, gid, name, render.bytes(sw))


def check_proxmox_node_swap(params, section):
    if section is None:
        return

    total = int(section.get("swap_total", 0) or 0)
    used = int(section.get("swap_used", 0) or 0)
    pct = (used / total * 100.0) if total > 0 else 0.0

    guests = list(section.get("guests", []))
    guests.sort(key=lambda g: g.get("swap", 0), reverse=True)
    active = [g for g in guests if g.get("swap", 0) > 0]

    # ---- state from configurable percent level ---------------------------
    levels = params.get("levels")  # (warn, crit) in percent, or None
    if total == 0:
        yield Result(state=State.OK, summary="No swap configured on this node")
        yield Metric("swap_used_percent", 0.0, boundaries=(0, 100))
        yield Metric("swap_used_bytes", 0, boundaries=(0, 0))
        return

    warn = crit = None
    state = State.OK
    if levels:
        warn, crit = levels
        if pct >= crit:
            state = State.CRIT
        elif pct >= warn:
            state = State.WARN

    top = active[:TOP_SUMMARY]
    top_txt = ", ".join(_guest_label(g) for g in top) or "no guest swap in use"
    yield Result(
        state=state,
        summary="Swap %.1f%% used (%s of %s), top: %s"
        % (pct, render.bytes(used), render.bytes(total), top_txt),
    )

    yield Metric(
        "swap_used_percent", pct,
        levels=(warn, crit) if levels else None,
        boundaries=(0, 100),
    )
    yield Metric("swap_used_bytes", used, boundaries=(0, total))

    # ---- details ---------------------------------------------------------
    lines = ["Top %d swap-consuming guests:" % TOP_DETAILS]
    if not active:
        lines.append("  (no VM or container is currently using node swap)")
    else:
        for rank, g in enumerate(active[:TOP_DETAILS], 1):
            typ, gid, name = g["type"], g["id"], g["name"]
            sw, lim = g["swap"], g.get("limit")
            extra = ""
            if lim:
                extra = "  (%.0f%% of %s swap limit)" % (
                    sw / lim * 100.0, render.bytes(lim))
            lines.append(
                ("  %2d. %-2s %5s  %-24s %-10s%s"
                 % (rank, typ, gid, name, render.bytes(sw), extra)).rstrip())

    guest_sum = sum(g.get("swap", 0) for g in guests)
    other = used - guest_sum
    lines += [
        "",
        "Node swap total     : %s" % render.bytes(total),
        "Node swap used      : %s (%.1f%%)" % (render.bytes(used), pct),
        "Guests swap total   : %s" % render.bytes(max(guest_sum, 0)),
        "Other (host/system) : %s" % (render.bytes(other) if other > 0 else "0 B"),
    ]
    if levels:
        lines.append("Levels              : WARN %g%% / CRIT %g%%" % (warn, crit))

    yield Result(state=State.OK, notice="\n".join(lines))


check_plugin_proxmox_node_swap = CheckPlugin(
    name="proxmox_node_swap",
    service_name="Proxmox Node Swap Usage",
    discovery_function=discover_proxmox_node_swap,
    check_function=check_proxmox_node_swap,
    check_default_parameters={"levels": (50.0, 80.0)},
    check_ruleset_name="proxmox_node_swap",
)
