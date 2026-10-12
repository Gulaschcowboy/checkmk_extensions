#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""LinOTP config sync status across cluster nodes (/monitoring/config).

A single-node LinOTP installation is also expected to report ``sync: true``
(nothing to desync from), so a false reading here is treated as WARN by
default rather than CRIT -- it is most useful on multi-node/HA setups, where
the user can raise this to CRIT via the check's parameters if desired.
"""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def parse_linotp_rest_config(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty section"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected data"}


def discover_linotp_rest_config(section: dict[str, Any]):
    yield Service()


def check_linotp_rest_config(params: dict[str, Any], section: dict[str, Any]):
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Could not read LinOTP config status"))
        return

    sync = section.get("sync")
    if sync is False:
        state_not_in_sync = State(params.get("state_not_in_sync", State.WARN.value))
        yield Result(state=state_not_in_sync, summary="Configuration is NOT in sync across nodes")
    else:
        yield Result(state=State.OK, summary="Configuration in sync")

    realms = section.get("realms")
    policies = section.get("policies")
    resolvers = sum(
        int(section.get(k) or 0) for k in ("ldapresolver", "sqlresolver", "passwdresolver") if k in section
    )
    details = []
    if realms is not None:
        details.append(f"{realms} realm(s)")
    details.append(f"{resolvers} resolver(s)")
    if policies is not None:
        details.append(f"{policies} polic{'y' if policies == 1 else 'ies'}")
    yield Result(state=State.OK, notice=", ".join(details))

    if realms is not None:
        yield Metric(name="linotp_rest_realms_configured", value=int(realms))
    yield Metric(name="linotp_rest_resolvers_configured", value=resolvers)
    if policies is not None:
        yield Metric(name="linotp_rest_policies", value=int(policies))


check_default_parameters_linotp_rest_config: dict[str, Any] = {"state_not_in_sync": State.WARN.value}

agent_section_linotp_rest_config = AgentSection(
    name="linotp_rest_config",
    parse_function=parse_linotp_rest_config,
)

check_plugin_linotp_rest_config = CheckPlugin(
    name="linotp_rest_config",
    service_name="LinOTP Config Sync",
    discovery_function=discover_linotp_rest_config,
    check_function=check_linotp_rest_config,
    check_default_parameters=check_default_parameters_linotp_rest_config,
    check_ruleset_name="linotp_rest_config",
)
