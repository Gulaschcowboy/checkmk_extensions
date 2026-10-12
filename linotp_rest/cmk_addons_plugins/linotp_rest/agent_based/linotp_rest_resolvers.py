#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""LinOTP per-resolver user counts (/monitoring/userinfo + /monitoring/activeUsers),
one Checkmk service per realm/resolver combination, directly on the queried host.

A resolver suddenly reporting 0 configured users typically means its
backend (LDAP/SQL) is unreachable or misconfigured -- this is the
availability signal for the user backends behind a realm, which LinOTP's
own monitoring API does not otherwise surface as an explicit health check.
"""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State, check_levels

ITEM_SEPARATOR = " / "


def parse_linotp_rest_resolvers(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty section"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected data"}


def discover_linotp_rest_resolvers(section: dict[str, Any]):
    if not section.get("ok"):
        return
    realms = section.get("realms")
    if not isinstance(realms, dict):
        return
    for realm, resolvers in realms.items():
        if not isinstance(resolvers, dict):
            continue
        for resolver in resolvers:
            yield Service(item=f"{realm}{ITEM_SEPARATOR}{resolver}")


def check_linotp_rest_resolvers(item: str, params: dict[str, Any], section: dict[str, Any]):
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Could not read resolver user counts"))
        return

    realm, _, resolver = item.partition(ITEM_SEPARATOR)
    realms = section.get("realms")
    resolvers = realms.get(realm) if isinstance(realms, dict) else None
    entry = resolvers.get(resolver) if isinstance(resolvers, dict) else None
    if not isinstance(entry, dict):
        yield Result(state=State.UNKNOWN, summary=f"Resolver {item!r} no longer reported by LinOTP")
        return

    total_users = entry.get("total_users")
    active_users = entry.get("active_users")

    if total_users is None:
        yield Result(state=State.UNKNOWN, summary="No user count reported")
    else:
        levels_lower = params.get("levels_lower_total_users")
        levels_upper = params.get("levels_upper_total_users")
        result, metric = check_levels(
            float(total_users),
            levels_lower=levels_lower,
            levels_upper=levels_upper,
            metric_name="linotp_rest_resolver_total_users",
            render_func=lambda v: f"{v:.0f} configured users",
            label="Configured users",
        )
        yield result
        yield metric

    if active_users is not None:
        yield Metric(name="linotp_rest_resolver_active_users", value=int(active_users))
        yield Result(state=State.OK, notice=f"{active_users} recently active users")


check_default_parameters_linotp_rest_resolvers: dict[str, Any] = {
    "levels_lower_total_users": ("fixed", (1.0, 0.0)),
    "levels_upper_total_users": ("no_levels", None),
}

agent_section_linotp_rest_resolvers = AgentSection(
    name="linotp_rest_resolvers",
    parse_function=parse_linotp_rest_resolvers,
)

check_plugin_linotp_rest_resolvers = CheckPlugin(
    name="linotp_rest_resolvers",
    service_name="LinOTP Resolver %s",
    discovery_function=discover_linotp_rest_resolvers,
    check_function=check_linotp_rest_resolvers,
    check_default_parameters=check_default_parameters_linotp_rest_resolvers,
    check_ruleset_name="linotp_rest_resolvers",
)
