#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Check plugin for the 'dnssec_health' special agent.

Section 'dnssec_health' (JSON, one object per line) -> service "DNSSEC <domain>".
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
)

Section = Mapping[str, Mapping[str, Any]]


def parse_dnssec_health(string_table: list[list[str]]) -> Section:
    section: dict[str, Mapping[str, Any]] = {}
    for line in string_table:
        if not line or not line[0].strip():
            continue
        try:
            data = json.loads(line[0])
        except ValueError:
            continue
        domain = data.get("domain")
        if not isinstance(domain, str):
            continue
        nameserver = data.get("nameserver")
        item = f"{domain} via {nameserver}" if nameserver else domain
        section[item] = data
    return section


agent_section_dnssec_health = AgentSection(
    name="dnssec_health",
    parse_function=parse_dnssec_health,
)


def discover_dnssec_health(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_dnssec_health(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    signed = data.get("signed")
    validated = data.get("validated")
    nameserver = data.get("nameserver")
    via = f" ({nameserver})" if nameserver else ""

    if data.get("error") and signed is None:
        yield Result(state=State.UNKNOWN, summary=f"Query problem{via}: {data['error']}")
        return

    if signed is False:
        yield Result(
            state=State(params["state_unsigned"]),
            summary="Domain is not DNSSEC-signed (no DNSKEY records)",
        )
        return

    if signed:
        yield Result(state=State.OK, summary="Domain is DNSSEC-signed (DNSKEY present)")

    if validated:
        yield Result(
            state=State.OK,
            summary=f"Resolver{via} validated the signature (AD bit set)",
        )
    else:
        yield Result(
            state=State(params["state_not_validated"]),
            summary=f"Resolver{via} did not set the AD bit "
            "(non-validating resolver, or validation failure)",
        )


check_plugin_dnssec_health = CheckPlugin(
    name="dnssec_health",
    service_name="DNSSEC %s",
    discovery_function=discover_dnssec_health,
    check_function=check_dnssec_health,
    check_ruleset_name="dnssec_health",
    check_default_parameters={
        "state_unsigned": 1,
        "state_not_validated": 1,
    },
)
