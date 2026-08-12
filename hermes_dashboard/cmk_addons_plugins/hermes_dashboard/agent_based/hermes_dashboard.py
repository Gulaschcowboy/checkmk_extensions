#!/usr/bin/env python3
"""Hermes Agent dashboard checks — overview, gateway, per-platform, per-component."""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def parse_hermes_dashboard(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_hermes_dashboard = AgentSection(
    name="hermes_dashboard",
    parse_function=parse_hermes_dashboard,
)


# --------------------------------------------------------------------------
# Overview: agent version, overall status, active sessions, update available
# --------------------------------------------------------------------------
def discover_hermes_dashboard(section):
    if section and "_error" not in section:
        yield Service()


def check_hermes_dashboard(params, section):
    if not section:
        yield Result(state=State.UNKNOWN, summary="No data from dashboard")
        return
    if "_error" in section:
        yield Result(state=State.CRIT,
                     summary="Dashboard unreachable: %s" % section["_error"])
        return

    overall = section.get("overall", "unknown")
    overall_map = {"ok": State.OK, "degraded": State.WARN, "error": State.CRIT}
    state = overall_map.get(str(overall).lower(), State.UNKNOWN)
    version = section.get("version", "unknown")
    summary = "Version %s, overall status: %s" % (version, overall)
    yield Result(state=state, summary=summary)

    if section.get("can_update_hermes"):
        update_state = State(params.get("state_update_available", 0))
        yield Result(state=update_state, summary="Update available")

    active_sessions = section.get("active_sessions")
    if active_sessions is not None:
        yield Result(state=State.OK, summary="Active sessions: %d" % active_sessions)
        yield Metric("active_sessions", float(active_sessions))

    gateway_busy = section.get("gateway_busy")
    if gateway_busy is not None:
        yield Result(state=State.OK, notice="Gateway busy: %s" % gateway_busy)


check_plugin_hermes_dashboard = CheckPlugin(
    name="hermes_dashboard",
    service_name="Hermes Dashboard",
    discovery_function=discover_hermes_dashboard,
    check_function=check_hermes_dashboard,
    check_default_parameters={"state_update_available": 0},
    check_ruleset_name="hermes_dashboard_overview",
)


# --------------------------------------------------------------------------
# Gateway process state
# --------------------------------------------------------------------------
def discover_hermes_dashboard_gateway(section):
    if section and "gateway_state" in section:
        yield Service()


def check_hermes_dashboard_gateway(params, section):
    if not section or "_error" in section:
        yield Result(state=State.UNKNOWN, summary="No gateway data")
        return
    gw_state = section.get("gateway_state", "unknown")
    running = section.get("gateway_running")
    state_map = {
        "running": State.OK,
        "stopped": State(params.get("state_stopped", 2)),
        "starting": State.WARN,
        "stopping": State.WARN,
        "error": State.CRIT,
        "crashed": State.CRIT,
    }
    state = state_map.get(str(gw_state).lower(), State.WARN)
    summary = "Gateway state: %s" % gw_state
    if not running and state == State.OK:
        state = State.WARN
    yield Result(state=state, summary=summary)

    exit_reason = section.get("gateway_exit_reason")
    if exit_reason:
        yield Result(state=State.WARN, summary="Last exit reason: %s" % exit_reason)

    mode = section.get("gateway_mode")
    if mode:
        yield Result(state=State.OK, notice="Gateway mode: %s" % mode)


check_plugin_hermes_dashboard_gateway = CheckPlugin(
    name="hermes_dashboard_gateway",
    sections=["hermes_dashboard"],
    service_name="Hermes Gateway",
    discovery_function=discover_hermes_dashboard_gateway,
    check_function=check_hermes_dashboard_gateway,
    check_default_parameters={"state_stopped": 2},
    check_ruleset_name="hermes_dashboard_gateway",
)


# --------------------------------------------------------------------------
# Per-platform connection state (Telegram, Discord, Slack, ...)
# --------------------------------------------------------------------------
def discover_hermes_dashboard_platform(section):
    platforms = section.get("gateway_platforms") if section else None
    if isinstance(platforms, dict):
        for name in platforms:
            yield Service(item=name)


def check_hermes_dashboard_platform(item, params, section):
    platforms = section.get("gateway_platforms") if section else None
    if not isinstance(platforms, dict) or item not in platforms:
        yield Result(state=State.UNKNOWN, summary="Platform not reported")
        return
    info = platforms[item]
    pstate = info.get("state", "unknown")
    state_map = {
        "connected": State.OK,
        "connecting": State.WARN,
        "disconnected": State(params.get("state_disconnected", 2)),
        "error": State.CRIT,
    }
    state = state_map.get(str(pstate).lower(), State.WARN)
    summary = "State: %s" % pstate
    err_code = info.get("error_code")
    err_msg = info.get("error_message")
    if err_code or err_msg:
        summary += " (%s: %s)" % (err_code, err_msg)
        state = State.worst(state, State.CRIT)
    yield Result(state=state, summary=summary)


check_plugin_hermes_dashboard_platform = CheckPlugin(
    name="hermes_dashboard_platform",
    sections=["hermes_dashboard"],
    service_name="Hermes Platform %s",
    discovery_function=discover_hermes_dashboard_platform,
    check_function=check_hermes_dashboard_platform,
    check_default_parameters={"state_disconnected": 2},
    check_ruleset_name="hermes_dashboard_platform",
)


# --------------------------------------------------------------------------
# Per-component health (gateway/dashboard/storage/platforms)
# --------------------------------------------------------------------------
def discover_hermes_dashboard_component(section):
    components = section.get("components") if section else None
    if isinstance(components, dict):
        for name in components:
            yield Service(item=name)


def check_hermes_dashboard_component(item, params, section):
    components = section.get("components") if section else None
    if not isinstance(components, dict) or item not in components:
        yield Result(state=State.UNKNOWN, summary="Component not reported")
        return
    info = components[item]
    if not isinstance(info, dict):
        yield Result(state=State.UNKNOWN, summary="Unparsable component data")
        return
    status = info.get("status", "unknown")
    state_map = {"ok": State.OK, "degraded": State.WARN, "error": State.CRIT}
    state = state_map.get(str(status).lower(), State.UNKNOWN)
    summary = "Status: %s" % status

    errors = info.get("recent_unhandled_errors")
    if errors:
        summary += ", recent unhandled errors: %d" % errors
        state = State.worst(state, State(params.get("state_recent_errors", 1)))

    configured = info.get("configured")
    connected = info.get("connected")
    if configured is not None and connected is not None:
        summary += ", connected: %s/%s" % (connected, configured)
        if connected < configured:
            state = State.worst(state, State(params.get("state_platform_gap", 1)))

    yield Result(state=state, summary=summary)


check_plugin_hermes_dashboard_component = CheckPlugin(
    name="hermes_dashboard_component",
    sections=["hermes_dashboard"],
    service_name="Hermes Component %s",
    discovery_function=discover_hermes_dashboard_component,
    check_function=check_hermes_dashboard_component,
    check_default_parameters={"state_recent_errors": 1, "state_platform_gap": 1},
    check_ruleset_name="hermes_dashboard_component",
)
