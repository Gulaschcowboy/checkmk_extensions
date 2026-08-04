#!/usr/bin/env python3
"""PBS jobs check — one service per configured prune/verify/sync/tape job.

The special agent emits, per job type, a list of configured jobs each carrying
its ``last`` task result (correlated from the node task history). One Checkmk
service is discovered per job, named e.g. "PBS Prune Job backup1" or
"PBS Verify Job my-verify".
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


# Job type -> (human label used in the service item)
_TYPE_LABELS = {
    "prune": "Prune",
    "verify": "Verify",
    "sync": "Sync",
    "tape": "Tape",
}


def parse_pbs_jobs(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_pbs_jobs = AgentSection(
    name="pbs_jobs",
    parse_function=parse_pbs_jobs,
)


def _iter_jobs(section):
    """Yield (item, jobtype, jobdict) for every configured job."""
    for jtype, label in _TYPE_LABELS.items():
        entries = section.get(jtype)
        if not isinstance(entries, list):
            continue
        for job in entries:
            jid = job.get("id") or job.get("store") or "unknown"
            item = "%s %s" % (label, jid)
            yield item, jtype, job


def discover_pbs_jobs(section):
    if not section:
        return
    for item, _jtype, _job in _iter_jobs(section):
        yield Service(item=item)


def _task_state(status):
    if status is None:
        return State.OK, "running"
    if status == "OK":
        return State.OK, "OK"
    if status.startswith("WARNINGS"):
        return State.WARN, status
    return State.CRIT, status


def check_pbs_jobs(item, params, section):
    if not section:
        return
    match = None
    for cand_item, jtype, job in _iter_jobs(section):
        if cand_item == item:
            match = (jtype, job)
            break
    if match is None:
        yield Result(state=State.UNKNOWN, summary="Job no longer configured")
        return

    jtype, job = match

    if job.get("disable"):
        yield Result(state=State(params.get("state_disabled", 0)),
                     summary="Job is disabled")

    store = job.get("store")
    if store:
        yield Result(state=State.OK, notice="Datastore: %s" % store)
    if job.get("schedule"):
        yield Result(state=State.OK, notice="Schedule: %s" % job["schedule"])
    if jtype == "sync" and job.get("remote"):
        yield Result(state=State.OK,
                     notice="Remote: %s:%s" % (job.get("remote"),
                                               job.get("remote_store", "")))
    if jtype == "tape":
        if job.get("pool"):
            yield Result(state=State.OK, notice="Pool: %s" % job["pool"])
        if job.get("drive"):
            yield Result(state=State.OK, notice="Drive: %s" % job["drive"])
    if jtype == "prune" and job.get("keep"):
        keep = ", ".join("%s=%s" % (k.replace("keep-", ""), v)
                         for k, v in sorted(job["keep"].items()))
        yield Result(state=State.OK, notice="Retention: %s" % keep)

    last = job.get("last") or {}
    status = last.get("status")
    endtime = last.get("endtime")
    starttime = last.get("starttime")

    if not last:
        if job.get("disable"):
            yield Result(state=State.OK, summary="No run recorded (disabled)")
        else:
            yield Result(state=State(params.get("state_never_run", 1)),
                         summary="No run found in task history")
        return

    state, txt = _task_state(status)
    if state == State.CRIT:
        state = State(params.get("state_failed", 2))
    elif state == State.WARN:
        state = State(params.get("state_warn", 1))

    if status is None:
        yield Result(state=State.OK, summary="Job is running")
        if starttime:
            running_for = time.time() - int(starttime)
            yield Result(state=State.OK,
                         summary="Running for %s" % render.timespan(running_for))
    else:
        yield Result(state=state, summary="Last result: %s" % txt)

    if endtime:
        age = time.time() - int(endtime)
        max_age = params.get("max_age")
        gstate = State.OK
        if max_age and not job.get("disable"):
            warn, crit = max_age
            if age >= crit:
                gstate = State.CRIT
            elif age >= warn:
                gstate = State.WARN
        yield Result(state=gstate, summary="Last run: %s ago" % render.timespan(age))
        yield Metric("last_age", age)


check_plugin_pbs_jobs = CheckPlugin(
    name="pbs_jobs",
    service_name="PBS Job %s",
    discovery_function=discover_pbs_jobs,
    check_function=check_pbs_jobs,
    check_default_parameters={
        "state_failed": 2,
        "state_warn": 1,
        "state_never_run": 1,
        "state_disabled": 0,
    },
    check_ruleset_name="pbs_jobs",
)
