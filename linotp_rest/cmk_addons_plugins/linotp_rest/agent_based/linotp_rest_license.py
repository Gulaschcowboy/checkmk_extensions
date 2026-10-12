#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""LinOTP license and support/grace status (/monitoring/license, /system/isSupportValid)."""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def parse_linotp_rest_license(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty section"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected data"}


def discover_linotp_rest_license(section: dict[str, Any]):
    yield Service()


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def check_linotp_rest_license(section: dict[str, Any]):
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Could not read LinOTP license status"))
        return

    support_valid = section.get("support_valid")
    grace_reason = section.get("grace_reason")

    if support_valid is False:
        yield Result(state=State.CRIT, summary="LinOTP support/license is not valid")
    elif grace_reason:
        yield Result(state=State.WARN, summary=str(grace_reason))
    else:
        yield Result(state=State.OK, summary="License OK")

    token_num = _to_int(section.get("token_num"))
    token_active = _to_int(section.get("token_active"))
    token_left = _to_int(section.get("token_left"))

    details = []
    if token_num is not None:
        details.append(f"{token_num} tokens licensed")
    if token_active is not None:
        details.append(f"{token_active} active")
    if token_left is not None:
        details.append(f"{token_left} left")
    if details:
        yield Result(state=State.OK, notice=", ".join(details))

    if token_num is not None:
        yield Metric(name="linotp_rest_token_num", value=token_num)
    if token_active is not None:
        yield Metric(name="linotp_rest_token_active", value=token_active)
    if token_left is not None:
        yield Metric(name="linotp_rest_token_left", value=token_left)


agent_section_linotp_rest_license = AgentSection(
    name="linotp_rest_license",
    parse_function=parse_linotp_rest_license,
)

check_plugin_linotp_rest_license = CheckPlugin(
    name="linotp_rest_license",
    service_name="LinOTP License",
    discovery_function=discover_linotp_rest_license,
    check_function=check_linotp_rest_license,
)
