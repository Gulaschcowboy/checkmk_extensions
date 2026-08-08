#!/usr/bin/env python3
"""Postfix mail queue depth check (one service per queue: deferred, active,
incoming, hold).

Section payload (JSON list):
    [{"queue": "deferred", "count": N}, {"queue": "deferred", "_error": ".."}, ...]
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def parse_pmg_queue(string_table):
    if not string_table:
        return []
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return []
    return data if isinstance(data, list) else []


agent_section_pmg_queue = AgentSection(
    name="pmg_queue",
    parse_function=parse_pmg_queue,
)


def discover_pmg_queue(section):
    for entry in section:
        queue = entry.get("queue")
        if queue:
            yield Service(item=queue)


def _levels(level_spec, default=(None, None)):
    """Unwrap a SimpleLevels-produced tagged tuple: ("fixed", (warn, crit))
    or ("no_levels", None). Falls back to treating an already-bare tuple
    as-is for back-compat with any pre-SimpleLevels stored value."""
    if isinstance(level_spec, tuple) and len(level_spec) == 2 and level_spec[0] in ("fixed", "no_levels"):
        kind, value = level_spec
        return value if kind == "fixed" else (None, None)
    if level_spec is None:
        return default
    return level_spec


def check_pmg_queue(item, params, section):
    entry = next((e for e in section if e.get("queue") == item), None)
    if entry is None:
        return
    if "_error" in entry:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % entry["_error"])
        return

    count = int(entry.get("count", 0))
    warn, crit = _levels(params.get("levels", ("fixed", (200.0, 1000.0))))
    state = State.OK
    if count >= crit:
        state = State.CRIT
    elif count >= warn:
        state = State.WARN
    yield Result(state=state, summary="%d mails in queue" % count)
    yield Metric("mail_queue_length", count, levels=(warn, crit))


check_plugin_pmg_queue = CheckPlugin(
    name="pmg_queue",
    sections=["pmg_queue"],
    service_name="PMG Postfix Queue %s",
    discovery_function=discover_pmg_queue,
    check_function=check_pmg_queue,
    check_default_parameters={"levels": ("fixed", (200.0, 1000.0))},
    check_ruleset_name="pmg_queue",
)
