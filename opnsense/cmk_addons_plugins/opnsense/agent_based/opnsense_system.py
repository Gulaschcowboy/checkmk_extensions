#!/usr/bin/env python3
"""OPNsense system check — subsystem status, uptime, load, memory, swap."""
import json
import re
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    render,
)


def parse_opnsense_system(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_opnsense_system = AgentSection(
    name="opnsense_system",
    parse_function=parse_opnsense_system,
)


def _uptime_seconds(uptime_str):
    # e.g. "3 days, 04:52:30"
    if not uptime_str:
        return None
    days = 0
    m = re.search(r"(\d+)\s+day", uptime_str)
    if m:
        days = int(m.group(1))
    hms = re.search(r"(\d{1,2}):(\d{2}):(\d{2})", uptime_str)
    secs = days * 86400
    if hms:
        secs += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
    return secs


# --------------------------------------------------------------------------
# System status + uptime + load
# --------------------------------------------------------------------------
def discover_opnsense_system(section):
    if section:
        yield Service()


def check_opnsense_system(section):
    if not section:
        return

    status = section.get("status", {})
    if isinstance(status, dict) and "_error" not in status:
        meta = status.get("metadata", {})
        subsystems = meta.get("subsystems", [])
        # collect subsystem messages with severity
        problems = []
        for sub in subsystems:
            if isinstance(sub, dict):
                sev = sub.get("status", 0)
                msg = sub.get("message", "")
                title = sub.get("title", "")
                if sev and sev > 2:
                    problems.append((sev, title, msg))
        if problems:
            worst = max(p[0] for p in problems)
            state = State.CRIT if worst >= 3 else State.WARN
            txt = "; ".join("%s: %s" % (t or "subsystem", m) for _, t, m in problems)
            yield Result(state=state, summary="Subsystem notifications: %s" % txt)
        else:
            yield Result(state=State.OK, summary="No pending subsystem notifications")

    time_info = section.get("time", {})
    if isinstance(time_info, dict) and "_error" not in time_info:
        up = _uptime_seconds(time_info.get("uptime", ""))
        if up is not None:
            yield Result(state=State.OK, summary="Uptime: %s" % render.timespan(up))
            yield Metric("uptime", up)
        loadavg = time_info.get("loadavg", "")
        m = re.findall(r"[\d.]+", loadavg)
        if len(m) >= 3:
            l1, l5, l15 = float(m[0]), float(m[1]), float(m[2])
            yield Result(state=State.OK,
                         summary="Load: %.2f/%.2f/%.2f" % (l1, l5, l15))
            yield Metric("load1", l1)
            yield Metric("load5", l5)
            yield Metric("load15", l15)


check_plugin_opnsense_system = CheckPlugin(
    name="opnsense_system",
    service_name="OPNsense System",
    discovery_function=discover_opnsense_system,
    check_function=check_opnsense_system,
)


# --------------------------------------------------------------------------
# Memory (+ swap)
# --------------------------------------------------------------------------
def discover_opnsense_memory(section):
    res = section.get("resources", {}) if section else {}
    if isinstance(res, dict) and res.get("memory"):
        yield Service()


def check_opnsense_memory(params, section):
    res = section.get("resources", {})
    if not isinstance(res, dict) or "_error" in res:
        yield Result(state=State.UNKNOWN, summary="No memory data")
        return
    mem = res.get("memory", {})
    try:
        total = int(mem.get("total", 0))
        used = int(mem.get("used", 0))
    except (ValueError, TypeError):
        yield Result(state=State.UNKNOWN, summary="Unparsable memory data")
        return
    if total <= 0:
        yield Result(state=State.UNKNOWN, summary="No memory total reported")
        return

    pct = 100.0 * used / total
    warn, crit = params.get("levels", (80.0, 90.0))
    state = State.OK
    if pct >= crit:
        state = State.CRIT
    elif pct >= warn:
        state = State.WARN
    yield Result(state=state,
                 summary="Used: %s of %s (%.1f%%)"
                 % (render.bytes(used), render.bytes(total), pct))
    yield Metric("mem_used", used, levels=(total * warn / 100, total * crit / 100),
                 boundaries=(0, total))
    yield Metric("mem_used_percent", pct, levels=(warn, crit), boundaries=(0, 100))

    # swap
    swap = section.get("swap", {})
    if isinstance(swap, dict) and "_error" not in swap:
        devs = swap.get("swap", [])
        s_total = s_used = 0
        for d in devs:
            try:
                s_total += int(d.get("total", 0)) * 1024
                s_used += int(d.get("used", 0)) * 1024
            except (ValueError, TypeError):
                pass
        if s_total > 0:
            s_pct = 100.0 * s_used / s_total
            yield Result(state=State.OK,
                         summary="Swap: %s of %s (%.1f%%)"
                         % (render.bytes(s_used), render.bytes(s_total), s_pct))
            yield Metric("swap_used", s_used, boundaries=(0, s_total))


check_plugin_opnsense_memory = CheckPlugin(
    name="opnsense_memory",
    sections=["opnsense_system"],
    service_name="OPNsense Memory",
    discovery_function=discover_opnsense_memory,
    check_function=check_opnsense_memory,
    check_default_parameters={"levels": (80.0, 90.0)},
    check_ruleset_name="opnsense_memory",
)
