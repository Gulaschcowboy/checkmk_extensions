#!/usr/bin/env python3
"""SpamAssassin rule-channel update status.

Section payload (JSON list):
    [{"channel": "sa-update", "update_avail": true/false,
      "version": "..", "update_version": "..", "last_updated": epoch}, ...]
    or {"_error": ".."} on API failure.
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Result,
    Service,
    State,
    render,
)


def parse_pmg_spamassassin(string_table):
    if not string_table:
        return []
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return []
    if isinstance(data, dict) and "_error" in data:
        return data
    return data if isinstance(data, list) else []


agent_section_pmg_spamassassin = AgentSection(
    name="pmg_spamassassin",
    parse_function=parse_pmg_spamassassin,
)


def discover_pmg_spamassassin(section):
    if isinstance(section, list):
        for entry in section:
            channel = entry.get("channel")
            if channel:
                yield Service(item=channel)


def check_pmg_spamassassin(item, params, section):
    if isinstance(section, dict) and "_error" in section:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % section["_error"])
        return

    entry = next((e for e in section if e.get("channel") == item), None)
    if entry is None:
        return

    version = entry.get("version", "unknown")
    update_avail = bool(entry.get("update_avail", False))
    update_version = entry.get("update_version")
    last_updated = entry.get("last_updated")

    summary_parts = ["Version %s" % version]
    if last_updated:
        summary_parts.append("last updated %s" % render.datetime(last_updated))

    if update_avail:
        state = State(params.get("update_avail_state", State.WARN.value))
        summary_parts.append("update available"
                             + (" (%s)" % update_version if update_version else ""))
    else:
        state = State.OK
        summary_parts.append("up to date")

    yield Result(state=state, summary=", ".join(summary_parts))


check_plugin_pmg_spamassassin = CheckPlugin(
    name="pmg_spamassassin",
    sections=["pmg_spamassassin"],
    service_name="PMG SpamAssassin %s",
    discovery_function=discover_pmg_spamassassin,
    check_function=check_pmg_spamassassin,
    check_default_parameters={"update_avail_state": State.WARN.value},
    check_ruleset_name="pmg_spamassassin",
)
