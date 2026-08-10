#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Metric, Result, Service, State


def _parse_json_lines(string_table: list[list[str]]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for row in string_table:
        raw = " ".join(row).strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            parsed.append(value)
    return parsed


def parse_homeassistant(string_table: list[list[str]]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    entities: dict[str, dict[str, Any]] = {}
    for entry in _parse_json_lines(string_table):
        if entry.get("kind") == "meta":
            meta = entry
        elif entry.get("kind") == "entity" and entry.get("entity_id"):
            entities[str(entry["entity_id"])] = entry
    return {"meta": meta, "entities": entities}


def discover_homeassistant(section: dict[str, Any]):
    for entity_id in sorted(section.get("entities", {})):
        yield Service(item=entity_id)


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _summary_text(value: Any) -> str:
    """Return a safe single-line representation for Checkmk Result.summary.

    Home Assistant string states may legitimately contain embedded newlines, for
    example geocoded addresses. Checkmk does not allow a newline in summary.
    Collapse all whitespace to single spaces and drop NUL characters while the
    unmodified value is retained in Result.details.
    """
    return " ".join(str(value).replace("\x00", "").split())


def _entity_details(
    *,
    item: str,
    friendly_name: str,
    state_value: str,
    unit: str,
    device_class: str,
    age: float | None,
) -> str:
    lines = [
        f"Entity: {item}",
        f"Friendly name: {friendly_name}",
        f"Device class: {device_class or 'n/a'}",
        f"Value: {state_value or 'no state'}",
    ]
    if unit:
        lines.append(f"Unit: {unit}")
    if age is not None:
        lines.append(f"Last update age: {age:.1f} s")
    return "\n".join(lines).replace("\x00", "�")


def check_homeassistant(item: str, section: dict[str, Any]):
    entity = section.get("entities", {}).get(item)
    if not entity:
        yield Result(state=State.UNKNOWN, summary="Entity is missing from Home Assistant data")
        return

    friendly_name_raw = str(entity.get("friendly_name") or item)
    state_value = str(entity.get("state") or "")
    unit = str(entity.get("unit") or "")
    device_class = str(entity.get("device_class") or "")
    age = _as_float(entity.get("age_seconds"))
    stale_after = _as_float(entity.get("stale_after"))
    if stale_after is None:
        stale_after = 0.0

    friendly_name = _summary_text(friendly_name_raw) or item
    state_summary = _summary_text(state_value)
    unit_summary = _summary_text(unit)
    details = _entity_details(
        item=item,
        friendly_name=friendly_name_raw,
        state_value=state_value,
        unit=unit,
        device_class=device_class,
        age=age,
    )

    if state_value.lower() in ("unknown", "unavailable", "none", ""):
        yield Result(
            state=State.UNKNOWN,
            summary=f"{friendly_name}: {state_summary or 'no state'}",
            details=details,
        )
        return

    summary = f"{friendly_name}: {state_summary}{(' ' + unit_summary) if unit_summary else ''}"
    if age is not None:
        summary += f", age {age:.0f} s"

    result_state = State.WARN if age is not None and stale_after > 0 and age > stale_after else State.OK
    yield Result(state=result_state, summary=summary, details=details)

    numeric = _as_float(state_value)
    if numeric is not None:
        yield Metric(name="homeassistant_value", value=numeric)


agent_section_homeassistant = AgentSection(
    name="homeassistant",
    parse_function=parse_homeassistant,
)

check_plugin_homeassistant = CheckPlugin(
    name="homeassistant",
    service_name="Home Assistant %s",
    discovery_function=discover_homeassistant,
    check_function=check_homeassistant,
)
