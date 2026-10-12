#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""LinOTP token counts per realm (/monitoring/tokens), one service per realm."""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Result, Service, State, check_levels


def parse_linotp_rest_tokens(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty section"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected data"}


def discover_linotp_rest_tokens(section: dict[str, Any]):
    if not section.get("ok"):
        return
    realms = section.get("realms")
    if not isinstance(realms, dict):
        return
    for realm in realms:
        yield Service(item=realm)


def check_linotp_rest_tokens(item: str, params: dict[str, Any], section: dict[str, Any]):
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Could not read token counts"))
        return

    realms = section.get("realms")
    entry = realms.get(item) if isinstance(realms, dict) else None
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary=f"Realm {item!r} no longer reported by LinOTP")
        return

    total = entry.get("total")
    total_users = entry.get("total_users")

    if total is None and total_users is None:
        yield Result(state=State.OK, summary="OK")
        return

    if total is not None:
        result, metric = check_levels(
            float(total),
            levels_lower=params.get("levels_lower_total"),
            levels_upper=params.get("levels_upper_total"),
            metric_name="linotp_rest_tokens_total",
            render_func=lambda v: f"{v:.0f} tokens",
            label="Tokens",
        )
        yield result
        yield metric

    if total_users is not None:
        result, metric = check_levels(
            float(total_users),
            levels_lower=params.get("levels_lower_total_users"),
            levels_upper=params.get("levels_upper_total_users"),
            metric_name="linotp_rest_tokens_total_users",
            render_func=lambda v: f"{v:.0f} users with tokens",
            label="Users with tokens",
        )
        yield result
        yield metric


check_default_parameters_linotp_rest_tokens: dict[str, Any] = {
    "levels_lower_total": ("no_levels", None),
    "levels_upper_total": ("no_levels", None),
    "levels_lower_total_users": ("no_levels", None),
    "levels_upper_total_users": ("no_levels", None),
}

agent_section_linotp_rest_tokens = AgentSection(
    name="linotp_rest_tokens",
    parse_function=parse_linotp_rest_tokens,
)

check_plugin_linotp_rest_tokens = CheckPlugin(
    name="linotp_rest_tokens",
    service_name="LinOTP Tokens %s",
    discovery_function=discover_linotp_rest_tokens,
    check_function=check_linotp_rest_tokens,
    check_default_parameters=check_default_parameters_linotp_rest_tokens,
    check_ruleset_name="linotp_rest_tokens",
)
