#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Server-side check plug-in for the "zfs_arc" agent section.
# ---------------------------------------------------------------------------
# Consumes the JSON emitted by the agent plug-in
# (cmk_addons_plugins/zfs_arc/agents/zfs_arc):
#
#   {"size": <bytes>, "c_max": <bytes>, "c_min": <bytes>,
#    "hits": <count>, "misses": <count>,
#    "memory_throttle_count": <count>, "mem_total": <bytes>}
#
# and produces the service "ZFS ARC cache usage":
#   * state from configurable percent levels on ARC-vs-max, ARC-vs-RAM and
#     (inverted) hit ratio, plus an unconditional WARN on ARC memory
#     throttling
#   * metrics: zfs_arc_used_percent, zfs_arc_ram_percent, zfs_arc_hit_ratio,
#     zfs_arc_size_bytes
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


def parse_zfs_arc(string_table):
    if not string_table:
        return None
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return None


agent_section_zfs_arc = AgentSection(
    name="zfs_arc",
    parse_function=parse_zfs_arc,
)


def discover_zfs_arc(section):
    if section is not None:
        yield Service()


def _levels_from_params(raw):
    """Normalise a 'levels_*' parameter to a (warn, crit) tuple or None.

    Accepts the SimpleLevels form ("fixed", (w, c)) / ("no_levels", None).
    """
    if isinstance(raw, (tuple, list)) and len(raw) == 2:
        tag, value = raw
        if tag == "fixed" and isinstance(value, (tuple, list)) and len(value) == 2:
            return (float(value[0]), float(value[1]))
        if tag == "no_levels":
            return None
        if isinstance(tag, (int, float)) and isinstance(value, (int, float)):
            return (float(tag), float(value))  # legacy bare (warn, crit)
    return None


def _state_upper(value, levels):
    if levels is None:
        return State.OK
    warn, crit = levels
    if value >= crit:
        return State.CRIT
    if value >= warn:
        return State.WARN
    return State.OK


def _state_lower(value, levels):
    if levels is None:
        return State.OK
    warn, crit = levels
    if value <= crit:
        return State.CRIT
    if value <= warn:
        return State.WARN
    return State.OK


def check_zfs_arc(params, section):
    if section is None:
        return

    size = int(section.get("size", 0) or 0)
    c_max = int(section.get("c_max", 0) or 0)
    hits = int(section.get("hits", 0) or 0)
    misses = int(section.get("misses", 0) or 0)
    throttle = int(section.get("memory_throttle_count", 0) or 0)
    mem_total = int(section.get("mem_total", 0) or 0)

    arc_pct = (size / c_max * 100.0) if c_max > 0 else 0.0
    ram_pct = (size / mem_total * 100.0) if mem_total > 0 else 0.0
    total_ops = hits + misses
    hit_ratio = (hits / total_ops * 100.0) if total_ops > 0 else 100.0

    levels_arc_pct = _levels_from_params(params.get("levels_arc_pct"))
    levels_ram_pct = _levels_from_params(params.get("levels_ram_pct"))
    levels_hit_ratio = _levels_from_params(params.get("levels_hit_ratio"))

    state_arc_pct = _state_upper(arc_pct, levels_arc_pct)
    state_ram_pct = _state_upper(ram_pct, levels_ram_pct)
    state_hit_ratio = _state_lower(hit_ratio, levels_hit_ratio)

    # Split into one Result per sub-metric so Checkmk attaches the WARN/CRIT
    # marker to the value that actually breached its levels, instead of
    # always tacking it onto the end of a single combined summary line.
    yield Result(
        state=state_arc_pct,
        summary="ARC %s of %s (%.0f%% of max)"
        % (
            render.bytes(size),
            render.bytes(c_max) if c_max else "n/a",
            arc_pct,
        ),
    )
    yield Result(
        state=state_ram_pct,
        summary="%.0f%% of RAM" % ram_pct,
    )
    yield Result(
        state=state_hit_ratio,
        summary="hit ratio %.1f%%" % hit_ratio,
    )

    yield Metric(
        "zfs_arc_used_percent", arc_pct,
        levels=levels_arc_pct, boundaries=(0, 100),
    )
    yield Metric(
        "zfs_arc_ram_percent", ram_pct,
        levels=levels_ram_pct, boundaries=(0, 100),
    )
    yield Metric(
        "zfs_arc_hit_ratio", hit_ratio,
        levels=levels_hit_ratio, boundaries=(0, 100),
    )
    yield Metric("zfs_arc_size_bytes", size, boundaries=(0, c_max or None))

    if throttle > 0:
        yield Result(
            state=State.WARN,
            notice="ARC memory throttle events: %d (host under memory pressure)" % throttle,
        )

    lines = [
        "ARC size            : %s" % render.bytes(size),
        "ARC max (c_max)     : %s" % (render.bytes(c_max) if c_max else "n/a"),
        "RAM total           : %s" % (render.bytes(mem_total) if mem_total else "n/a"),
        "Hit ratio           : %.1f%% (%d hits / %d misses)" % (hit_ratio, hits, misses),
        "Memory throttle     : %d" % throttle,
    ]
    yield Result(state=State.OK, notice="\n".join(lines))


check_plugin_zfs_arc = CheckPlugin(
    name="zfs_arc",
    service_name="ZFS ARC cache usage",
    discovery_function=discover_zfs_arc,
    check_function=check_zfs_arc,
    check_default_parameters={
        "levels_arc_pct": ("fixed", (90.0, 97.0)),
        "levels_ram_pct": ("fixed", (80.0, 90.0)),
        "levels_hit_ratio": ("fixed", (85.0, 75.0)),
    },
    check_ruleset_name="zfs_arc",
)
