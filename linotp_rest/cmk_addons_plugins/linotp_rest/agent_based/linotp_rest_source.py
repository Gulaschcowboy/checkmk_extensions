#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Own run health of the LinOTP REST special agent."""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def parse_linotp_rest_source(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty special agent output"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid special agent JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected special agent data"}


def discover_linotp_rest_source(section: dict[str, Any]):
    yield Service()


def check_linotp_rest_source(section: dict[str, Any]):
    duration = float(section.get("duration_seconds") or 0.0)

    if not section.get("ok"):
        error = str(section.get("error") or "LinOTP query failed")
        yield Result(state=State.CRIT, summary=error)
        yield Metric(name="linotp_rest_query_time", value=duration)
        return

    realms = int(section.get("realms") or 0)
    url = str(section.get("url") or "")
    summary = f"{url} OK, {realms} realm(s), {duration:.2f} s query time" if url else (
        f"OK, {realms} realm(s), {duration:.2f} s query time"
    )
    yield Result(state=State.OK, summary=summary)
    yield Metric(name="linotp_rest_realms", value=realms)
    yield Metric(name="linotp_rest_query_time", value=duration)


agent_section_linotp_rest_source = AgentSection(
    name="linotp_rest_source",
    parse_function=parse_linotp_rest_source,
)

check_plugin_linotp_rest_source = CheckPlugin(
    name="linotp_rest_source",
    service_name="LinOTP Source",
    discovery_function=discover_linotp_rest_source,
    check_function=check_linotp_rest_source,
)
