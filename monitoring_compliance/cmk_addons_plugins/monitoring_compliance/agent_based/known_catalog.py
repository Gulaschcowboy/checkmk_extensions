#!/usr/bin/env python3
# Checkmk Monitoring Compliance - Known Catalog (read-only reference)
#
# An informational service that lists the application types the compliance
# detection knows about (the built-in alias/signature/title tables), annotated
# with whether a covering check plug-in is currently available on this site.
# It is read-only: it never depends on host state and is always OK. It is
# separate from the observed-capabilities database.
#
# Enable "Report known catalog" in the special-agent rule on one host to get a
# single instance (section monitoring_compliance_catalog).

import json
import re
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

# The catalog knowledge lives in the main check module. Import it; on any
# failure fall back to empty tables so this plug-in always loads.
try:
    from cmk_addons.plugins.monitoring_compliance.agent_based.monitoring_compliance import (  # noqa: E501
        ALIASES,
        HINTS,
        TITLES,
        _SIGNATURES_RAW,
    )
except Exception:  # noqa: BLE001
    ALIASES, HINTS, TITLES = {}, {}, {}
    _SIGNATURES_RAW = ()


def _parse(string_table: StringTable) -> Mapping[str, Any] | None:
    raw = "".join(part for row in string_table for part in row)
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


agent_section_monitoring_compliance_catalog = AgentSection(
    name="monitoring_compliance_catalog",
    parse_function=_parse,
)


def _plugin_token(name: str) -> str:
    m = re.match(r"[a-z0-9]+", str(name).lower())
    return m.group(0) if m else ""


def _clean_pattern(pat: str) -> str:
    out = pat.replace(r"\b", "").replace(r"\s*", " ").replace("\\", "")
    return out.strip()


def discover_known_catalog(section) -> DiscoveryResult:
    if section is not None:
        yield Service()


def check_known_catalog(section) -> CheckResult:
    if section is None:
        return

    available = [str(p) for p in section.get("available_plugins", []) or []]
    avail_tokens = {_plugin_token(p) for p in available}

    tokens = sorted(TITLES.keys())
    total = len(tokens)
    available_count = 0
    items: list[tuple[bool, str]] = []

    for tok in tokens:
        title = TITLES.get(tok, tok)
        is_avail = tok in avail_tokens
        if is_avail:
            available_count += 1
        patterns_raw = [p for p, t in _SIGNATURES_RAW if t == tok]
        patterns_raw += sorted({a for a, t in ALIASES.items() if t == tok})
        seen: set[str] = set()
        patterns: list[str] = []
        for p in patterns_raw:
            cleaned = _clean_pattern(p)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                patterns.append(cleaned)
        status = ("monitorable on this site" if is_avail
                  else "no covering plug-in on this site")
        note = f"{title} [{tok}] \u2013 {status}"
        if patterns:
            note += f"; matches: {', '.join(patterns[:6])}"
        items.append((is_avail, note))

    if total == 0:
        yield Result(
            state=State.OK,
            summary="Known catalog is empty (catalog tables unavailable)",
        )
        return

    yield Result(
        state=State.OK,
        summary=(f"{total} known application types, {available_count} "
                 "monitorable on this site"),
    )
    yield Metric("known_catalog_total", total)
    yield Metric("known_catalog_available", available_count)

    # available first, then by name
    for _is_avail, note in sorted(items, key=lambda x: (not x[0], x[1])):
        yield Result(state=State.OK, notice=note)


check_plugin_monitoring_compliance_known_catalog = CheckPlugin(
    name="monitoring_compliance_known_catalog",
    sections=["monitoring_compliance_catalog"],
    service_name="Checkmk Known Catalog",
    discovery_function=discover_known_catalog,
    check_function=check_known_catalog,
)
