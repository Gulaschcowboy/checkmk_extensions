#!/usr/bin/env python3
"""PMG spam/virus quarantine size checks.

Section payload:
    {"spam": {"count":.., "mbytes":.., "avgspam":.., "avgbytes":..}
             | {"_error": ..},
     "virus": {"count":.., "mbytes":.., "avgbytes":..} | {"_error": ..}}
"""
import json
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def parse_pmg_quarantine(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pmg_quarantine = AgentSection(
    name="pmg_quarantine",
    parse_function=parse_pmg_quarantine,
)


def _check_quarantine(kind, params, entry, extra_summary=""):
    if not isinstance(entry, dict) or "_error" in entry:
        err = entry.get("_error") if isinstance(entry, dict) else "no data"
        yield Result(state=State.UNKNOWN, summary="API error: %s" % err)
        return

    count = int(entry.get("count", 0))
    mbytes = float(entry.get("mbytes", 0))

    warn, crit = _levels(params.get("count_levels", ("no_levels", None)))
    state = State.OK
    if crit is not None and count >= crit:
        state = State.CRIT
    elif warn is not None and count >= warn:
        state = State.WARN

    summary = "%d mails, %.1f MB" % (count, mbytes)
    if extra_summary:
        summary += ", " + extra_summary
    yield Result(state=state, summary=summary)
    yield Metric("pmg_quarantine_count", count,
                 levels=(warn, crit) if warn is not None else None)
    yield Metric("pmg_quarantine_mbytes", mbytes)


def discover_pmg_quarantine_spam(section):
    if isinstance(section.get("spam"), dict) and "_error" not in section["spam"]:
        yield Service()


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


def check_pmg_quarantine_spam(params, section):
    entry = section.get("spam", {})
    avgspam = entry.get("avgspam") if isinstance(entry, dict) else None
    extra = "avg. spam level %.1f" % float(avgspam) if avgspam is not None else ""
    yield from _check_quarantine("spam", params, entry, extra)
    if isinstance(entry, dict) and avgspam is not None:
        yield Metric("pmg_quarantine_avgspam", float(avgspam))


check_plugin_pmg_quarantine_spam = CheckPlugin(
    name="pmg_quarantine_spam",
    sections=["pmg_quarantine"],
    service_name="PMG Spam Quarantine Statistics",
    discovery_function=discover_pmg_quarantine_spam,
    check_function=check_pmg_quarantine_spam,
    check_default_parameters={"count_levels": ("no_levels", None)},
    check_ruleset_name="pmg_quarantine_spam",
)


def discover_pmg_quarantine_virus(section):
    if isinstance(section.get("virus"), dict) and "_error" not in section["virus"]:
        yield Service()


def check_pmg_quarantine_virus(params, section):
    entry = section.get("virus", {})
    yield from _check_quarantine("virus", params, entry)


check_plugin_pmg_quarantine_virus = CheckPlugin(
    name="pmg_quarantine_virus",
    sections=["pmg_quarantine"],
    service_name="PMG Virus Quarantine Statistics",
    discovery_function=discover_pmg_quarantine_virus,
    check_function=check_pmg_quarantine_virus,
    check_default_parameters={"count_levels": ("fixed", (1.0, 1.0))},
    check_ruleset_name="pmg_quarantine_virus",
)


# --- Quarantine queue (current backlog: spam / virus / attachment) ----------
def parse_pmg_quarantine_queue(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pmg_quarantine_queue = AgentSection(
    name="pmg_quarantine_queue",
    parse_function=parse_pmg_quarantine_queue,
)


def _discover_quarantine_queue(qtype):
    def _discover(section):
        entry = section.get(qtype)
        if isinstance(entry, dict) and "_error" in entry:
            return
        if entry is not None:
            yield Service()
    return _discover


def _check_quarantine_queue(qtype, params, section):
    entry = section.get(qtype)
    if isinstance(entry, dict) and "_error" in entry:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % entry["_error"])
        return
    if entry is None:
        yield Result(state=State.UNKNOWN, summary="no data")
        return

    count = int(entry)
    warn, crit = _levels(params.get("count_levels", ("fixed", (1.0, 10.0))))
    state = State.OK
    if crit is not None and count >= crit:
        state = State.CRIT
    elif warn is not None and count >= warn:
        state = State.WARN

    yield Result(state=state, summary="%d mails" % count)
    yield Metric("pmg_quarantine_queue_count", count,
                 levels=(warn, crit) if warn is not None else None)


discover_pmg_quarantine_queue_spam = _discover_quarantine_queue("spam")
discover_pmg_quarantine_queue_virus = _discover_quarantine_queue("virus")
discover_pmg_quarantine_queue_attachment = _discover_quarantine_queue("attachment")


def check_pmg_quarantine_queue_spam(params, section):
    yield from _check_quarantine_queue("spam", params, section)


def check_pmg_quarantine_queue_virus(params, section):
    yield from _check_quarantine_queue("virus", params, section)


def check_pmg_quarantine_queue_attachment(params, section):
    yield from _check_quarantine_queue("attachment", params, section)


check_plugin_pmg_quarantine_queue_spam = CheckPlugin(
    name="pmg_quarantine_queue_spam",
    sections=["pmg_quarantine_queue"],
    service_name="PMG Spam Quarantine Queue",
    discovery_function=discover_pmg_quarantine_queue_spam,
    check_function=check_pmg_quarantine_queue_spam,
    check_default_parameters={"count_levels": ("fixed", (1.0, 10.0))},
    check_ruleset_name="pmg_quarantine_queue_spam",
)

check_plugin_pmg_quarantine_queue_virus = CheckPlugin(
    name="pmg_quarantine_queue_virus",
    sections=["pmg_quarantine_queue"],
    service_name="PMG Virus Quarantine Queue",
    discovery_function=discover_pmg_quarantine_queue_virus,
    check_function=check_pmg_quarantine_queue_virus,
    check_default_parameters={"count_levels": ("fixed", (1.0, 10.0))},
    check_ruleset_name="pmg_quarantine_queue_virus",
)

check_plugin_pmg_quarantine_queue_attachment = CheckPlugin(
    name="pmg_quarantine_queue_attachment",
    sections=["pmg_quarantine_queue"],
    service_name="PMG Attachment Quarantine Queue",
    discovery_function=discover_pmg_quarantine_queue_attachment,
    check_function=check_pmg_quarantine_queue_attachment,
    check_default_parameters={"count_levels": ("fixed", (1.0, 10.0))},
    check_ruleset_name="pmg_quarantine_queue_attachment",
)
