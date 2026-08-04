#!/usr/bin/env python3
"""PBS garbage-collection check — one service per datastore GC."""
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


def parse_pbs_gc(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pbs_gc = AgentSection(
    name="pbs_gc",
    parse_function=parse_pbs_gc,
)


def discover_pbs_gc(section):
    if "_error" in section:
        return
    for store in section:
        yield Service(item=store)


def _task_state(status):
    """Map a PBS task status string to a Checkmk state + text."""
    if status is None:
        return State.OK, "running"
    if status == "OK":
        return State.OK, "OK"
    if status.startswith("WARNINGS"):
        return State.WARN, status
    return State.CRIT, status


def check_pbs_gc(item, params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % section["_error"])
        return
    gc = section.get(item)
    if gc is None:
        yield Result(state=State.UNKNOWN, summary="No GC data for datastore")
        return

    last = gc.get("last") or {}
    status = last.get("status")
    endtime = last.get("endtime")
    starttime = last.get("starttime")

    if not last:
        yield Result(state=State(params.get("state_never_run", 1)),
                     summary="No garbage collection has run yet")
    else:
        state, txt = _task_state(status)
        # Respect a user override for the failure state.
        if state == State.CRIT:
            state = State(params.get("state_failed", 2))
        elif state == State.WARN:
            state = State(params.get("state_warn", 1))
        if status is None:
            yield Result(state=State.OK, summary="Garbage collection is running")
        else:
            yield Result(state=state, summary="Last GC result: %s" % txt)

        if endtime:
            age = time.time() - int(endtime)
            summary = "Last run: %s ago" % render.timespan(age)
            max_age = params.get("max_age")
            gstate = State.OK
            if max_age:
                warn, crit = max_age
                if age >= crit:
                    gstate = State.CRIT
                elif age >= warn:
                    gstate = State.WARN
            yield Result(state=gstate, summary=summary)
            yield Metric("last_age", age)
        elif starttime and status is None:
            running_for = time.time() - int(starttime)
            yield Result(state=State.OK,
                         summary="Running for %s" % render.timespan(running_for))

    # Reclaimed / integrity metrics from the GC status snapshot.
    removed = gc.get("removed_bytes")
    if removed is not None:
        yield Result(state=State.OK,
                     notice="Removed in last GC: %s (%s chunks)"
                     % (render.bytes(int(removed)), gc.get("removed_chunks", 0)))
        yield Metric("removed_bytes", int(removed))

    bad = gc.get("removed_bad", 0) or 0
    still_bad = gc.get("still_bad", 0) or 0
    if still_bad:
        yield Result(state=State.CRIT,
                     summary="%d bad chunks still present" % still_bad)
    yield Metric("removed_bad_chunks", int(bad))
    yield Metric("still_bad_chunks", int(still_bad))

    disk_bytes = gc.get("disk_bytes")
    if disk_bytes is not None:
        yield Metric("disk_bytes", int(disk_bytes))

    nxt = gc.get("next_run")
    if nxt:
        delta = int(nxt) - time.time()
        if delta > 0:
            yield Result(state=State.OK,
                         notice="Next run in %s" % render.timespan(delta))
    if gc.get("schedule"):
        yield Result(state=State.OK, notice="Schedule: %s" % gc["schedule"])


check_plugin_pbs_gc = CheckPlugin(
    name="pbs_gc",
    service_name="PBS GC %s",
    discovery_function=discover_pbs_gc,
    check_function=check_pbs_gc,
    check_default_parameters={
        "state_failed": 2,
        "state_warn": 1,
        "state_never_run": 1,
    },
    check_ruleset_name="pbs_gc",
)
