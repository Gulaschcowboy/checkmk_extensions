#!/usr/bin/env python3
# Checkmk Monitoring Compliance - Capability Database statistics
#
# Second service that reports statistics about the persistent Capability
# Database written by the compliance check (size, number of entries, entries
# by type, monitorable/monitored counts, distinct hosts/tokens, last update).
#
# The data comes from the special agent (section monitoring_compliance_capdb),
# which reads the database file server-side. Enable "Report capability database
# statistics" in the special-agent rule on exactly one host (e.g. the Checkmk
# server host) to get a single instance of this service.

import json
import time
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
)


def _parse(string_table: StringTable) -> Mapping[str, Any] | None:
    raw = "".join(part for row in string_table for part in row)
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


agent_section_monitoring_compliance_capdb = AgentSection(
    name="monitoring_compliance_capdb",
    parse_function=_parse,
)


def _human_size(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(num) < 1024.0:
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TiB"


def _human_age(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


def discover_capdb(section) -> DiscoveryResult:
    if section is not None:
        yield Service()


def check_capdb(params: Mapping[str, Any], section) -> CheckResult:
    if section is None:
        return

    if not section.get("exists"):
        yield Result(
            state=State(int(params.get("state_if_missing", 1))),
            summary=("Capability database not found at "
                     f"{section.get('path', '?')} \u2013 no compliance checks "
                     "have written to it yet, or it is disabled"),
        )
        return

    total = int(section.get("total", 0))
    size = int(section.get("size_bytes", 0))
    monitorable = int(section.get("monitorable", 0))
    monitored = int(section.get("monitored", 0))
    hosts = int(section.get("hosts", 0))
    tokens = int(section.get("tokens", 0))
    updated = int(section.get("updated_ts", 0))
    by_type = section.get("by_type", {}) or {}

    age = max(0, int(time.time()) - updated) if updated else None

    state = State.OK
    stale_suffix = ""
    warn = params.get("max_update_age_warn")
    crit = params.get("max_update_age_crit")
    if age is not None:
        if crit and age >= int(crit):
            state = State.CRIT
            stale_suffix = f" \u2013 not updated for {_human_age(age)}"
        elif warn and age >= int(warn):
            state = State.WARN
            stale_suffix = f" \u2013 not updated for {_human_age(age)}"

    summary = (f"{total} entries, {monitorable} monitorable, "
               f"{monitored} monitored, size {_human_size(size)}{stale_suffix}")
    yield Result(state=state, summary=summary)

    yield Metric("capability_db_entries", total)
    yield Metric("capability_db_size", size)
    yield Metric("capability_db_monitorable", monitorable)
    yield Metric("capability_db_monitored", monitored)
    yield Metric("capability_db_hosts", hosts)

    if by_type:
        line = ", ".join(f"{t}: {n}" for t, n in sorted(by_type.items()))
        yield Result(state=State.OK, notice=f"Entries by type: {line}")
    yield Result(state=State.OK,
                 notice=f"Distinct hosts: {hosts}, distinct tokens: {tokens}")
    if age is not None:
        yield Result(state=State.OK, notice=f"Last update: {_human_age(age)} ago")

    errors = section.get("errors") or []
    if errors:
        yield Result(state=State.OK, notice="Notes: " + "; ".join(errors))


check_plugin_monitoring_compliance_capdb = CheckPlugin(
    name="monitoring_compliance_capdb",
    sections=["monitoring_compliance_capdb"],
    service_name="Checkmk Capability Database",
    discovery_function=discover_capdb,
    check_function=check_capdb,
    check_ruleset_name="monitoring_compliance_capdb",
    check_default_parameters={"state_if_missing": 1},
)
