#!/usr/bin/env python3
"""PMG node-level checks: status/uptime, subscription, pending APT updates,
certificate expiry.

Section payload (JSON):
    {"status": {"uptime":.., "insync":.., "current-kernel": {...}} | {"_error"},
     "subscription": {"status": "Active"/"NotFound"/.., "nextduedate": "..",
                       ...} | {"_error"},
     "updates": [{"Package":.., "OldVersion":.., "Version":..}, ...] | {"_error"},
     "certificates": [{"subject":.., "notafter": epoch, "san": [...]}, ...]
                      | {"_error"}}
"""
import json
import time
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    render,
)


def parse_pmg_node(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pmg_node = AgentSection(
    name="pmg_node",
    parse_function=parse_pmg_node,
)


# --------------------------------------------------------------------------
# Node status / uptime / cluster sync
# --------------------------------------------------------------------------
def discover_pmg_node_status(section):
    status = section.get("status") if section else None
    if isinstance(status, dict) and "_error" not in status:
        yield Service()


def check_pmg_node_status(section):
    status = section.get("status", {})
    if not isinstance(status, dict) or "_error" in status:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % status.get("_error", "no data"))
        return

    uptime = status.get("uptime")
    insync = status.get("insync")
    kernel = status.get("current-kernel", {})

    if uptime is not None:
        yield Result(state=State.OK, summary="Up since %s" % render.timespan(uptime))
        yield Metric("uptime", float(uptime))

    if insync is not None:
        # PMG has returned insync as both a JSON bool and 0/1 across
        # versions -- normalize.
        if bool(int(insync)):
            yield Result(state=State.OK, summary="Cluster database in sync")
        else:
            yield Result(state=State.WARN, summary="Cluster database not in sync")

    release = kernel.get("release")
    if release:
        yield Result(state=State.OK, summary="Kernel %s" % release)


check_plugin_pmg_node_status = CheckPlugin(
    name="pmg_node_status",
    sections=["pmg_node"],
    service_name="PMG Node Status",
    discovery_function=discover_pmg_node_status,
    check_function=check_pmg_node_status,
)


# --------------------------------------------------------------------------
# Subscription status
# --------------------------------------------------------------------------
def discover_pmg_subscription(section):
    sub = section.get("subscription") if section else None
    if isinstance(sub, dict) and "_error" not in sub:
        yield Service()


def check_pmg_subscription(section):
    sub = section.get("subscription", {})
    if not isinstance(sub, dict) or "_error" in sub:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % sub.get("_error", "no data"))
        return

    status = sub.get("status", "unknown")
    level = sub.get("level")
    nextduedate = sub.get("nextduedate")

    summary = "Status: %s" % status
    if level:
        summary += " (%s)" % level
    if nextduedate:
        summary += ", next due %s" % nextduedate

    state = State.OK
    if status.lower() in ("notfound", "invalid", "suspended"):
        state = State.WARN
    if status.lower() == "no subscription" or status.lower() == "notfound":
        # No subscription is a normal/expected state for community users --
        # informational only, not a fault.
        state = State.OK

    yield Result(state=state, summary=summary)


check_plugin_pmg_subscription = CheckPlugin(
    name="pmg_subscription",
    sections=["pmg_node"],
    service_name="PMG Subscription",
    discovery_function=discover_pmg_subscription,
    check_function=check_pmg_subscription,
)


# --------------------------------------------------------------------------
# Pending APT package updates
# --------------------------------------------------------------------------
def discover_pmg_updates(section):
    updates = section.get("updates") if section else None
    if isinstance(updates, list):
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


def check_pmg_updates(params, section):
    updates = section.get("updates")
    if isinstance(updates, dict) and "_error" in updates:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % updates["_error"])
        return
    if not isinstance(updates, list):
        yield Result(state=State.UNKNOWN, summary="No update data")
        return

    count = len(updates)
    warn, crit = _levels(params.get("levels", ("fixed", (1.0, 20.0))))
    state = State.OK
    if crit is not None and count >= crit:
        state = State.CRIT
    elif warn is not None and count >= warn:
        state = State.WARN

    summary = "%d pending package update(s)" % count
    if updates and count <= 10:
        names = [u.get("Package", "?") for u in updates]
        summary += ": " + ", ".join(names)
    yield Result(state=state, summary=summary)
    yield Metric("pmg_updates_pending", count)


check_plugin_pmg_updates = CheckPlugin(
    name="pmg_updates",
    sections=["pmg_node"],
    service_name="PMG Pending Updates",
    discovery_function=discover_pmg_updates,
    check_function=check_pmg_updates,
    check_default_parameters={"levels": ("fixed", (1.0, 20.0))},
    check_ruleset_name="pmg_updates",
)


# --------------------------------------------------------------------------
# Certificate expiry
# --------------------------------------------------------------------------
def discover_pmg_certificates(section):
    certs = section.get("certificates") if section else None
    if isinstance(certs, list):
        for cert in certs:
            subject = cert.get("subject") or cert.get("filename")
            if subject:
                yield Service(item=subject)


def check_pmg_certificates(item, params, section):
    certs = section.get("certificates")
    if isinstance(certs, dict) and "_error" in certs:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % certs["_error"])
        return
    if not isinstance(certs, list):
        return

    cert = next((c for c in certs
                if (c.get("subject") or c.get("filename")) == item), None)
    if cert is None:
        return

    notafter = cert.get("notafter")
    if notafter is None:
        yield Result(state=State.OK, summary="No expiry information")
        return

    remaining = notafter - time.time()
    warn, crit = _levels(params.get("expiry_levels", ("fixed", (30 * 86400.0, 7 * 86400.0))))
    state = State.OK
    if remaining <= crit:
        state = State.CRIT
    elif remaining <= warn:
        state = State.WARN

    if remaining >= 0:
        summary = "Expires in %s" % render.timespan(remaining)
    else:
        summary = "Expired %s ago" % render.timespan(-remaining)
    yield Result(state=state, summary=summary)
    yield Metric("pmg_cert_remaining", remaining,
                 levels=(warn, crit) if state != State.OK else None)


check_plugin_pmg_certificates = CheckPlugin(
    name="pmg_certificates",
    sections=["pmg_node"],
    service_name="PMG Certificate %s",
    discovery_function=discover_pmg_certificates,
    check_function=check_pmg_certificates,
    check_default_parameters={"expiry_levels": ("fixed", (30 * 86400.0, 7 * 86400.0))},
    check_ruleset_name="pmg_certificates",
)
