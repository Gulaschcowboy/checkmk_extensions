#!/usr/bin/env python3
"""OPNsense package audit ("pkg audit", known vulnerable packages).

The agent triggers core/firmware/audit at most every N minutes and caches
the log of the last finished run, e.g.:
    python313-3.13.18 is vulnerable:
      Python -- poplib module ...
      CVE: CVE-2025-15367
    1 problem(s) in 1 package(s) found.

The service shows the age of that result separately, so a stale audit is
never presented as fresh.
"""
import json
import re
import time

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    check_levels,
    render,
)


def parse_opnsense_audit(string_table):
    if not string_table:
        return {}
    try:
        data = json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}
    return data if isinstance(data, dict) else {}


agent_section_opnsense_audit = AgentSection(
    name="opnsense_audit",
    parse_function=parse_opnsense_audit,
)


def parse_audit_log(log):
    """Return (problems, {package: [cve, ...]})."""
    packages = {}
    current = None
    for line in log.splitlines():
        m = re.match(r"^(\S+) is vulnerable:?\s*$", line)
        if m:
            current = m.group(1)
            packages.setdefault(current, [])
            continue
        m = re.match(r"^\s*CVE:\s*(.+)$", line)
        if m and current:
            for cve in m.group(1).split():
                if cve not in packages[current]:
                    packages[current].append(cve)
    m = re.search(r"(\d+) problem\(s\)", log)
    problems = int(m.group(1)) if m else len(packages)
    return problems, packages


def discover_opnsense_audit(section):
    if section and section.get("enabled", True):
        yield Service()


def check_opnsense_audit(params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN, summary="Agent error: %s" % section["_error"])
        return
    if not section.get("enabled", True):
        yield Result(state=State.UNKNOWN,
                     summary="Package audit disabled in the special agent rule")
        return

    log = section.get("log")
    if not log:
        if section.get("error"):
            yield Result(state=State.UNKNOWN,
                         summary="Could not start audit: %s" % section["error"])
        else:
            yield Result(state=State.OK,
                         summary="No audit result yet (audit is running)")
        return

    if "ERROR" in log.upper() and "is vulnerable" not in log \
            and "problem(s)" not in log and "0 problem" not in log:
        last = [ln for ln in log.splitlines() if ln.strip() and "***" not in ln]
        yield Result(state=State(params.get("state_audit_error", 1)),
                     summary="Audit failed: %s" % (last[-1] if last else "unknown error"))
    else:
        problems, packages = parse_audit_log(log)
        state = State.OK if problems == 0 else State(params.get("state_vulnerable", 1))
        if problems == 0:
            summary = "No known vulnerabilities"
        else:
            summary = "%d problem(s) in %d package(s): %s" % (
                problems, len(packages), ", ".join(sorted(packages)))
        yield Result(state=state, summary=summary)
        yield Metric("opnsense_vulnerable_packages", len(packages))
        if packages:
            yield Result(state=State.OK, notice="\n".join(
                "%s: %s" % (pkg, ", ".join(cves) or "no CVE id")
                for pkg, cves in sorted(packages.items())))

    # Age of the cached result (technical timestamp, shown separately).
    last_run = section.get("last_run")
    if last_run:
        age = max(0.0, time.time() - float(last_run))
        interval = float(section.get("interval") or 0)
        levels = params.get("levels_age")
        if levels is None and interval:
            # default: result older than 2 / 4 audit intervals
            levels = ("fixed", (2 * interval + 3600, 4 * interval + 3600))
        yield from check_levels(
            age,
            levels_upper=levels,
            render_func=render.timespan,
            label="Result age",
            boundaries=(0, None),
        )
    if section.get("pending"):
        yield Result(state=State.OK, notice="A new audit run is in progress")


check_plugin_opnsense_audit = CheckPlugin(
    name="opnsense_audit",
    sections=["opnsense_audit"],
    service_name="OPNsense Package audit",
    discovery_function=discover_opnsense_audit,
    check_function=check_opnsense_audit,
    check_default_parameters={
        "state_vulnerable": 1,
        "state_audit_error": 1,
    },
    check_ruleset_name="opnsense_audit",
)
