#!/usr/bin/env python3
"""ClamAV virus signature database freshness check.

Section payload (JSON list):
    [{"type": "main"/"daily"/"bytecode"/..., "version": "..",
      "nsigs": N, "build_time": "Tue 12 Nov ..."}, ...]
    or {"_error": ".."} on API failure.
"""
import json
import time
from email.utils import parsedate_to_datetime

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    render,
)


def parse_pmg_clamav(string_table):
    if not string_table:
        return []
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return []
    if isinstance(data, dict) and "_error" in data:
        return data
    return data if isinstance(data, list) else []


agent_section_pmg_clamav = AgentSection(
    name="pmg_clamav",
    parse_function=parse_pmg_clamav,
)


def _db_type(entry):
    # PMG's API has used both "type" and "name" for the database
    # identifier across versions -- accept either.
    return entry.get("type") or entry.get("name")


def discover_pmg_clamav(section):
    if isinstance(section, list):
        for entry in section:
            db_type = _db_type(entry)
            if db_type:
                yield Service(item=db_type)


def _parse_build_time(build_time):
    try:
        return parsedate_to_datetime(build_time).timestamp()
    except (TypeError, ValueError):
        return None


def _levels(level_spec, default=(None, None)):
    """Unwrap a SimpleLevels-produced tagged tuple: ("fixed", (warn, crit))
    or ("no_levels", None). Falls back to treating an already-bare tuple
    as-is for back-compat with any pre-SimpleLevels stored value."""
    if isinstance(level_spec, tuple) and len(level_spec) == 2 and level_spec[0] in ("fixed", "no_levels"):
        kind, value = level_spec
        return value if kind == "fixed" else (None, None)
    if level_spec is None:
        return default
    return level_spec


def check_pmg_clamav(item, params, section):
    if isinstance(section, dict) and "_error" in section:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % section["_error"])
        return

    entry = next((e for e in section if _db_type(e) == item), None)
    if entry is None:
        return

    version = entry.get("version", "unknown")
    nsigs = entry.get("nsigs")
    build_time = entry.get("build_time")

    summary = "Version %s" % version
    if nsigs is not None:
        summary += ", %d signatures" % int(nsigs)
        yield Metric("pmg_clamav_nsigs", int(nsigs))

    warn, crit = _levels(params.get("age_levels", ("fixed", (172800.0, 604800.0))))  # 2d / 7d
    build_ts = _parse_build_time(build_time) if build_time else None
    if build_ts is None:
        yield Result(state=State.OK, summary=summary + " (build time unknown)")
        return

    age = time.time() - build_ts
    state = State.OK
    if age >= crit:
        state = State.CRIT
    elif age >= warn:
        state = State.WARN
    summary += ", age %s" % render.timespan(age)
    yield Result(state=state, summary=summary)
    yield Metric("pmg_clamav_age", age, levels=(warn, crit))


check_plugin_pmg_clamav = CheckPlugin(
    name="pmg_clamav",
    sections=["pmg_clamav"],
    service_name="PMG ClamAV DB %s",
    discovery_function=discover_pmg_clamav,
    check_function=check_pmg_clamav,
    check_default_parameters={"age_levels": ("fixed", (172800.0, 604800.0))},
    check_ruleset_name="pmg_clamav",
)
