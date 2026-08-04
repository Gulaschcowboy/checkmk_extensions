#!/usr/bin/env python3
"""PBS node check — CPU, load, memory, swap, uptime, root fs, subscription."""
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


def parse_pbs_node(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pbs_node = AgentSection(
    name="pbs_node",
    parse_function=parse_pbs_node,
)


# --------------------------------------------------------------------------
# Node: CPU + load + uptime
# --------------------------------------------------------------------------
def discover_pbs_node(section):
    if section and "_error" not in section:
        yield Service()


def check_pbs_node(params, section):
    if not section:
        return
    if "_error" in section:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % section["_error"])
        return

    cpus = section.get("cpuinfo", {}).get("cpus")
    cpu = section.get("cpu")
    if cpu is not None:
        pct = float(cpu) * 100.0
        warn, crit = params.get("cpu_levels", (80.0, 90.0))
        state = State.OK
        if pct >= crit:
            state = State.CRIT
        elif pct >= warn:
            state = State.WARN
        yield Result(state=state, summary="CPU utilization: %.1f%%" % pct)
        yield Metric("util", pct, levels=(warn, crit), boundaries=(0, 100))

    io_wait = section.get("wait")
    if io_wait is not None:
        yield Metric("io_wait", float(io_wait) * 100.0)

    loadavg = section.get("loadavg")
    if isinstance(loadavg, list) and len(loadavg) >= 3:
        l1, l5, l15 = float(loadavg[0]), float(loadavg[1]), float(loadavg[2])
        summary = "Load average (1/5/15 min): %.2f/%.2f/%.2f" % (l1, l5, l15)
        if cpus:
            summary += " (%d CPUs)" % cpus
        yield Result(state=State.OK, summary=summary)
        yield Metric("load1", l1)
        yield Metric("load5", l5)
        yield Metric("load15", l15)

    uptime = section.get("uptime")
    if uptime is not None:
        yield Result(state=State.OK, summary="Uptime: %s" % render.timespan(int(uptime)))
        yield Metric("uptime", int(uptime))

    kver = section.get("current-kernel", {}).get("release")
    if kver:
        yield Result(state=State.OK, notice="Kernel: %s" % kver)


check_plugin_pbs_node = CheckPlugin(
    name="pbs_node",
    service_name="PBS Node",
    discovery_function=discover_pbs_node,
    check_function=check_pbs_node,
    check_default_parameters={"cpu_levels": (80.0, 90.0)},
    check_ruleset_name="pbs_node",
)


# --------------------------------------------------------------------------
# Node memory (+ swap)
# --------------------------------------------------------------------------
def discover_pbs_memory(section):
    if section and isinstance(section.get("memory"), dict):
        yield Service()


def _levels_state(pct, warn, crit):
    if pct >= crit:
        return State.CRIT
    if pct >= warn:
        return State.WARN
    return State.OK


def check_pbs_memory(params, section):
    if not section or "_error" in section:
        yield Result(state=State.UNKNOWN, summary="No memory data")
        return
    mem = section.get("memory", {})
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
    state = _levels_state(pct, warn, crit)
    yield Result(state=state,
                 summary="RAM used: %s of %s (%.1f%%)"
                 % (render.bytes(used), render.bytes(total), pct))
    yield Metric("mem_used", used, levels=(total * warn / 100, total * crit / 100),
                 boundaries=(0, total))
    yield Metric("mem_used_percent", pct, levels=(warn, crit), boundaries=(0, 100))

    swap = section.get("swap", {})
    if isinstance(swap, dict):
        try:
            s_total = int(swap.get("total", 0))
            s_used = int(swap.get("used", 0))
        except (ValueError, TypeError):
            s_total = s_used = 0
        if s_total > 0:
            s_pct = 100.0 * s_used / s_total
            yield Result(state=State.OK,
                         summary="Swap used: %s of %s (%.1f%%)"
                         % (render.bytes(s_used), render.bytes(s_total), s_pct))
            yield Metric("swap_used", s_used, boundaries=(0, s_total))


check_plugin_pbs_memory = CheckPlugin(
    name="pbs_memory",
    sections=["pbs_node"],
    service_name="PBS Node Memory",
    discovery_function=discover_pbs_memory,
    check_function=check_pbs_memory,
    check_default_parameters={"levels": (80.0, 90.0)},
    check_ruleset_name="pbs_memory",
)


# --------------------------------------------------------------------------
# Node root filesystem
# --------------------------------------------------------------------------
def discover_pbs_rootfs(section):
    if section and isinstance(section.get("root"), dict):
        yield Service()


def check_pbs_rootfs(params, section):
    if not section or "_error" in section:
        yield Result(state=State.UNKNOWN, summary="No root filesystem data")
        return
    root = section.get("root", {})
    try:
        total = int(root.get("total", 0))
        used = int(root.get("used", 0))
    except (ValueError, TypeError):
        yield Result(state=State.UNKNOWN, summary="Unparsable root fs data")
        return
    if total <= 0:
        yield Result(state=State.UNKNOWN, summary="No root fs total reported")
        return
    pct = 100.0 * used / total
    warn, crit = params.get("levels", (80.0, 90.0))
    state = _levels_state(pct, warn, crit)
    yield Result(state=state,
                 summary="Used: %s of %s (%.1f%%)"
                 % (render.bytes(used), render.bytes(total), pct))
    yield Metric("fs_used", used, levels=(total * warn / 100, total * crit / 100),
                 boundaries=(0, total))
    yield Metric("fs_used_percent", pct, levels=(warn, crit), boundaries=(0, 100))


check_plugin_pbs_rootfs = CheckPlugin(
    name="pbs_rootfs",
    sections=["pbs_node"],
    service_name="PBS Node Root FS",
    discovery_function=discover_pbs_rootfs,
    check_function=check_pbs_rootfs,
    check_default_parameters={"levels": (80.0, 90.0)},
    check_ruleset_name="pbs_rootfs",
)


# --------------------------------------------------------------------------
# Subscription
# --------------------------------------------------------------------------
def discover_pbs_subscription(section):
    if section and isinstance(section.get("subscription"), dict):
        yield Service()


def check_pbs_subscription(params, section):
    sub = section.get("subscription", {}) if section else {}
    if not isinstance(sub, dict) or "_error" in sub:
        yield Result(state=State.UNKNOWN, summary="No subscription data")
        return
    status = sub.get("status", "unknown")
    message = sub.get("message", "")
    mapping = {
        "active": State.OK,
        "new": State.OK,
        "notfound": State(params.get("state_notfound", 1)),
        "invalid": State.CRIT,
        "expired": State.CRIT,
        "suspended": State.WARN,
    }
    state = mapping.get(str(status).lower(), State.WARN)
    summary = "Subscription status: %s" % status
    if message:
        summary += " (%s)" % message
    yield Result(state=state, summary=summary)


check_plugin_pbs_subscription = CheckPlugin(
    name="pbs_subscription",
    sections=["pbs_node"],
    service_name="PBS Subscription",
    discovery_function=discover_pbs_subscription,
    check_function=check_pbs_subscription,
    check_default_parameters={"state_notfound": 1},
    check_ruleset_name="pbs_subscription",
)
