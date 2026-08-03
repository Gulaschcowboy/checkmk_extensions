#!/usr/bin/env python3
"""OPNsense services check — one Checkmk service per OPNsense service."""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Result,
    Service,
    State,
)


def parse_opnsense_services(string_table):
    if not string_table:
        return {}
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}
    if "_error" in data:
        return data
    services = {}
    for row in data.get("rows", []):
        item = row.get("id") or row.get("name")
        if not item:
            continue
        services[item] = {
            "name": row.get("name", item),
            "description": row.get("description", ""),
            "running": int(row.get("running", 0)),
            "locked": int(row.get("locked", 0)),
        }
    return services


agent_section_opnsense_services = AgentSection(
    name="opnsense_services",
    parse_function=parse_opnsense_services,
)


def discover_opnsense_services(section):
    if "_error" in section:
        return
    for item in section:
        yield Service(item=item)


def check_opnsense_services(item, params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % section["_error"])
        return
    svc = section.get(item)
    if svc is None:
        # service vanished since discovery
        yield Result(state=State(params.get("state_if_stale", 3)),
                     summary="Service not found in API output")
        return

    desc = svc["description"] or svc["name"]
    if svc["running"]:
        yield Result(state=State.OK, summary="%s: running" % desc)
    else:
        state = State(params.get("state_not_running", 2))
        yield Result(state=state, summary="%s: stopped" % desc)

    if svc["locked"]:
        yield Result(state=State.OK, notice="Service is locked (system service)")


check_plugin_opnsense_services = CheckPlugin(
    name="opnsense_services",
    service_name="OPNsense Service %s",
    discovery_function=discover_opnsense_services,
    check_function=check_opnsense_services,
    check_default_parameters={"state_not_running": 2, "state_if_stale": 3},
    check_ruleset_name="opnsense_services",
)
