#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def parse_citrix_ddc_rest_source(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty special agent output"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid special agent JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected special agent data"}


def discover_citrix_ddc_rest_source(section: dict[str, Any]):
    yield Service()


def check_citrix_ddc_rest_source(section: dict[str, Any]):
    duration = float(section.get("duration_seconds") or 0.0)

    if not section.get("ok"):
        error = str(section.get("error") or "Citrix DDC REST query failed")
        yield Result(state=State.CRIT, summary=error)
        yield Metric(name="citrix_ddc_rest_query_time", value=duration)
        return

    machines = int(section.get("machines") or 0)
    sessions = int(section.get("sessions") or 0)
    ddc = str(section.get("ddc") or "")

    summary = f"DDC {ddc} OK, {machines} machines, {sessions} sessions, {duration:.2f} s query time" if ddc else (
        f"OK, {machines} machines, {sessions} sessions, {duration:.2f} s query time"
    )
    yield Result(state=State.OK, summary=summary)
    yield Metric(name="citrix_ddc_rest_machines", value=machines)
    yield Metric(name="citrix_ddc_rest_sessions", value=sessions)
    yield Metric(name="citrix_ddc_rest_query_time", value=duration)


agent_section_citrix_ddc_rest_source = AgentSection(
    name="citrix_ddc_rest_source",
    parse_function=parse_citrix_ddc_rest_source,
)

check_plugin_citrix_ddc_rest_source = CheckPlugin(
    name="citrix_ddc_rest_source",
    service_name="Citrix DDC Statistics",
    discovery_function=discover_citrix_ddc_rest_source,
    check_function=check_citrix_ddc_rest_source,
)
