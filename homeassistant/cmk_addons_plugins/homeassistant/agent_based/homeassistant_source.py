#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def _summary_text(value: Any) -> str:
    return " ".join(str(value).replace("\x00", "").split())


def parse_homeassistant_source(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty special agent output"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid special agent JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected special agent data"}


def discover_homeassistant_source(section: dict[str, Any]):
    yield Service()


def check_homeassistant_source(section: dict[str, Any]):
    if not section.get("ok"):
        error = str(section.get("error") or "Home Assistant query failed")
        yield Result(
            state=State.CRIT,
            summary=_summary_text(error) or "Home Assistant query failed",
            details=error.replace("\x00", "�"),
        )
        return

    warnings = section.get("warnings") or []
    state = State.WARN if warnings else State.OK
    selected = int(section.get("selected_entities") or 0)
    emitted = int(section.get("emitted_entities") or 0)
    hosts = int(section.get("generated_hosts") or 0)
    duration = float(section.get("duration_seconds") or 0.0)

    summary = f"API OK, {emitted}/{selected} entities on {hosts} piggyback hosts, {duration:.2f} s"
    details = "\n".join(str(warning) for warning in warnings) if warnings else "Home Assistant REST and WebSocket queries completed successfully."
    yield Result(state=state, summary=summary, details=details)
    yield Metric(name="homeassistant_entities", value=emitted)
    yield Metric(name="homeassistant_hosts", value=hosts)
    yield Metric(name="homeassistant_query_time", value=duration)


agent_section_homeassistant_source = AgentSection(
    name="homeassistant_source",
    parse_function=parse_homeassistant_source,
)

check_plugin_homeassistant_source = CheckPlugin(
    name="homeassistant_source",
    service_name="Home Assistant API",
    discovery_function=discover_homeassistant_source,
    check_function=check_homeassistant_source,
)
