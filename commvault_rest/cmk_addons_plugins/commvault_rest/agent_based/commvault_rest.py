#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check plugins for agent_commvault_rest.

Every section is a JSON object: {"data": ...} or {"error": "..."}. An error
payload makes the services of that group UNKNOWN instead of vanishing.
Field names and states are taken from a real CommServe 11 SP44 dump; job
states that were not seen there (failed, killed, ...) are mapped by name
prefix and are configurable.
"""
from __future__ import annotations

import json
import time
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
    check_levels,
    get_value_store,
    render,
)
from cmk.plugins.lib.df import FILESYSTEM_DEFAULT_PARAMS, df_check_filesystem_single


def _parse_json(string_table: StringTable) -> Any:
    if not string_table:
        return None
    try:
        return json.loads("".join(line[0] for line in string_table if line))
    except (ValueError, IndexError):
        return {"error": "section is not valid JSON"}


agent_section_commvault_rest_source = AgentSection(name="commvault_rest_source", parse_function=_parse_json)
agent_section_commvault_rest_jobs = AgentSection(name="commvault_rest_jobs", parse_function=_parse_json)
agent_section_commvault_rest_active_jobs = AgentSection(name="commvault_rest_active_jobs", parse_function=_parse_json)
agent_section_commvault_rest_storage = AgentSection(name="commvault_rest_storage", parse_function=_parse_json)
agent_section_commvault_rest_vms = AgentSection(name="commvault_rest_vms", parse_function=_parse_json)
agent_section_commvault_rest_vm = AgentSection(name="commvault_rest_vm", parse_function=_parse_json)
agent_section_commvault_rest_mediaagents = AgentSection(name="commvault_rest_mediaagents", parse_function=_parse_json)
agent_section_commvault_rest_license = AgentSection(name="commvault_rest_license", parse_function=_parse_json)
agent_section_commvault_rest_license_usage = AgentSection(name="commvault_rest_license_usage",
                                                          parse_function=_parse_json)


def _error(section) -> Result | None:
    if section is None:
        return Result(state=State.UNKNOWN, summary="No data")
    if not isinstance(section, dict):
        return Result(state=State.UNKNOWN, summary="Unexpected section format")
    if "error" in section:
        return Result(state=State.UNKNOWN, summary=f"API error: {section['error']}")
    return None


def _levels(params, key):
    """SimpleLevels value ("fixed", (w, c)) / ("no_levels", None); plain tuples accepted."""
    value = params.get(key)
    if value is None:
        return None
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
        return None if value[0] == "no_levels" else value
    return ("fixed", tuple(value))


def _oneline(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _lookback_text(jobs: dict) -> str:
    lookback = jobs.get("lookback")
    return f" ({render.timespan(float(lookback))})" if lookback else ""


def _page_size_text(jobs: dict) -> str:
    return f", page size {jobs['page_size']}" if jobs.get("page_size") else ""


def _age(ts: int, now: float) -> float:
    return max(now - ts, 0.0)


def _fetched(section: dict, what: str) -> Result:
    """The API returns no timestamps for these values: make the query time visible."""
    ts = section.get("fetched")
    when = render.datetime(float(ts)) if ts else "unknown time"
    return Result(state=State.OK, notice=f"{what} queried live from the CommServe at {when} "
                                         "(the API reports no own timestamp)")


# --------------------------------------------------------------------------- CommServe / source

def discover_source(section) -> DiscoveryResult:
    if section:
        yield Service()


def check_source(section) -> CheckResult:
    if not isinstance(section, dict):
        yield Result(state=State.UNKNOWN, summary="No data")
        return
    duration = float(section.get("duration") or 0.0)
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Agent run failed"))
        yield Metric("commvault_rest_duration", duration)
        return

    cs = section.get("commserv") or {}
    if cs:
        yield Result(state=State.OK, summary=f"CommServe {cs.get('host') or '?'}, version {cs.get('version') or '?'}")
        if cs.get("timezone"):
            yield Result(state=State.OK, notice=f"Time zone: {cs['timezone']}")
    errors = section.get("errors") or {}
    for group, msg in sorted(errors.items()):
        yield Result(state=State.WARN, summary=f"{group}: {_oneline(msg)}")

    jobs = section.get("jobs")
    if isinstance(jobs, dict):
        yield Result(
            state=State.OK,
            notice=(f"Jobs in lookback{_lookback_text(jobs)}: {jobs.get('total')} "
                    f"(reported {jobs.get('total_reported')}, {jobs.get('pages')} page(s)"
                    f"{_page_size_text(jobs)}); skipped: {jobs.get('tlog_skipped')} SQL transaction log, "
                    f"{jobs.get('vsa_child_skipped', 0)} VM child jobs (see VM services), "
                    f"{jobs.get('restore_skipped')} restore, {jobs.get('no_subclient')} without subclient "
                    f"(aux copy, DDB, workflows, ...)"),
        )
        if jobs.get("truncated"):
            yield Result(state=State.WARN, summary="Job list truncated (page limit reached)")
    yield Result(state=State.OK, notice=f"Agent version {section.get('version')}, URL {section.get('url')}")
    yield from check_levels(duration, metric_name="commvault_rest_duration", render_func=render.timespan,
                            label="Agent run time")


check_plugin_commvault_rest_source = CheckPlugin(
    name="commvault_rest_source",
    service_name="Commvault CommServe",
    discovery_function=discover_source,
    check_function=check_source,
)


# --------------------------------------------------------------------------- Jobs per subclient

JOB_STATE_DEFAULTS = {
    "state_completed": 0,
    "state_completed_warnings": 1,
    "state_completed_errors": 1,
    "state_committed": 1,
    "state_failed": 2,
    "state_killed": 2,
    "state_other": 1,
    "state_no_job": 1,
    "state_no_success": 1,
}


def job_status_key(status: str) -> str:
    s = status.strip().lower()
    if s == "completed":
        return "state_completed"
    if s.startswith("completed"):
        if "error" in s:
            return "state_completed_errors"
        if "warning" in s:
            return "state_completed_warnings"
        return "state_other"
    for prefix, key in (("committed", "state_committed"), ("failed", "state_failed"), ("killed", "state_killed")):
        if s.startswith(prefix):
            return key
    return "state_other"


def _is_success(status: str) -> bool:
    return status.strip().lower().startswith("completed")


def _job_label(job: dict) -> str:
    level = f", {job['level']}" if job.get("level") else ""
    return f"job {job.get('id')} ({job.get('type') or '?'}{level})"


def discover_jobs(section) -> DiscoveryResult:
    if isinstance(section, dict) and isinstance(section.get("data"), dict):
        for item in section["data"].get("items") or {}:
            yield Service(item=item)


def check_jobs(item: str, params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    data = section.get("data") or {}
    jobs = (data.get("items") or {}).get(item)
    lookback = int(data.get("lookback") or 0)
    if not jobs:
        yield Result(state=State(params.get("state_no_job", 1)),
                     summary=f"No job within the lookback period ({render.timespan(lookback)})")
        return

    now = time.time()
    finished = [j for j in jobs if j.get("end")]
    running = [j for j in jobs if not j.get("end")]

    if finished:
        last = finished[0]
        state = State(params.get(job_status_key(last.get("status", "")), 1))
        yield Result(
            state=state,
            summary=(f"Last {_job_label(last)}: {last.get('status') or 'unknown'}, ended "
                     f"{render.datetime(last['end'])} ({render.timespan(_age(last['end'], now))} ago)"),
        )
        if last.get("pending"):
            yield Result(state=State.OK, notice=f"Reason: {_oneline(last['pending'], 500)}")
        yield Result(state=State.OK, notice=f"Last job run time: {render.timespan(last.get('elapsed') or 0)}")
    else:
        yield Result(state=State.OK, summary="No finished job within the lookback period yet")

    for job in running:
        pct = f", {job['percent']}%" if job.get("percent") is not None else ""
        pending = f", {_oneline(job['pending'])}" if job.get("pending") else ""
        yield Result(state=State.OK, summary=(f"Active {_job_label(job)}: {job.get('status')}{pct}, running for "
                                              f"{render.timespan(job.get('elapsed') or 0)}{pending}"))

    success = next((j for j in finished if _is_success(j.get("status", ""))), None)
    if success:
        yield from check_levels(
            _age(success["end"], now),
            levels_upper=_levels(params, "max_age_success"),
            metric_name="commvault_rest_backup_age",
            render_func=render.timespan,
            label="Last successful job",
        )
    elif finished:
        yield Result(state=State(params.get("state_no_success", 1)),
                     summary=f"No successful job within the lookback period ({render.timespan(lookback)})")

    history = ", ".join(f"{j.get('id')}: {j.get('status')}" for j in finished[:10])
    if history:
        yield Result(state=State.OK, notice=f"Recent jobs: {history}")


check_plugin_commvault_rest_job = CheckPlugin(
    name="commvault_rest_job",
    sections=["commvault_rest_jobs"],
    service_name="Commvault Job %s",
    discovery_function=discover_jobs,
    check_function=check_jobs,
    check_default_parameters=JOB_STATE_DEFAULTS,
    check_ruleset_name="commvault_rest_job",
)


# --------------------------------------------------------------------------- Active jobs

def discover_active_jobs(section) -> DiscoveryResult:
    if section:
        yield Service()


def _active_label(job: dict) -> str:
    what = job.get("item") or job.get("type") or "?"
    return f"{job.get('id')} {job.get('type')} [{what}]"


def _runtime_levels(params, job_type: str, global_levels):
    """Levels for one active job: first matching per-type entry, else the global levels."""
    wanted = job_type.strip().casefold()
    for entry in params.get("max_runtime_per_type") or []:
        types = [t.strip() for t in entry.get("job_types") or [] if t.strip()]
        if wanted in (t.casefold() for t in types):
            levels = _levels(entry, "max_runtime")
            return levels, f"limit for job type '{job_type}'" if levels else f"no limit for job type '{job_type}'"
    return global_levels, "global limit" if global_levels else "no global limit"


def check_active_jobs(params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    jobs = section.get("data") or []
    by_status: dict[str, int] = {}
    for job in jobs:
        by_status[job.get("status") or "?"] = by_status.get(job.get("status") or "?", 0) + 1
    counts = ", ".join(f"{n} {s.lower()}" for s, n in sorted(by_status.items()))
    yield Result(state=State.OK, summary=f"{len(jobs)} active job(s)" + (f" ({counts})" if counts else ""))
    yield Metric("commvault_rest_active_jobs", len(jobs))
    yield Metric("commvault_rest_waiting_jobs",
                 sum(n for s, n in by_status.items() if s.lower() in ("waiting", "pending", "queued", "suspended")))

    global_levels = _levels(params, "max_runtime")
    worst = None
    for job in sorted(jobs, key=lambda j: j.get("elapsed") or 0, reverse=True):
        elapsed = float(job.get("elapsed") or 0)
        pending = f" - {_oneline(job['pending'], 300)}" if job.get("pending") else ""
        levels, source = _runtime_levels(params, job.get("type") or "", global_levels)
        results = list(check_levels(elapsed, levels_upper=levels, render_func=render.timespan,
                                    label=f"Job {_active_label(job)} {job.get('status')}"))
        res = Result(state=results[0].state, summary=f"{results[0].summary} [{source}]")
        if res.state is not State.OK:
            yield Result(state=res.state, summary=f"{res.summary}{pending}")
        else:
            yield Result(state=State.OK, notice=f"{res.summary}{pending}")


check_plugin_commvault_rest_active_jobs = CheckPlugin(
    name="commvault_rest_active_jobs",
    service_name="Commvault Active Jobs",
    discovery_function=discover_active_jobs,
    check_function=check_active_jobs,
    check_default_parameters={"max_runtime": ("fixed", (24 * 3600.0, 72 * 3600.0))},
    check_ruleset_name="commvault_rest_active_jobs",
)


# --------------------------------------------------------------------------- Storage pools

def _pools(section) -> dict[str, dict]:
    if not isinstance(section, dict) or not isinstance(section.get("data"), list):
        return {}
    return {p["name"]: p for p in section["data"] if isinstance(p, dict) and p.get("name")}


def discover_storage(section) -> DiscoveryResult:
    for name in _pools(section):
        yield Service(item=name)


def pool_status_state(status: str) -> State:
    s = status.strip().lower()
    if s.startswith("online"):
        return State.WARN if "(" in s else State.OK
    if s.startswith("offline"):
        return State.CRIT
    return State.WARN


def check_storage(item: str, params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    pool = _pools(section).get(item)
    if pool is None:
        return
    status = pool.get("status") or "unknown"
    yield Result(state=pool_status_state(status), summary=f"Status: {_oneline(status, 300)}")
    cap = float(pool.get("capacity_mb") or 0)
    if cap > 0:
        free = float(pool.get("free_mb") or 0)
        yield from df_check_filesystem_single(get_value_store(), item, cap, free, 0, None, None, params,
                                              this_time=time.time())
        yield Result(state=State.OK, notice=f"Usable free: {render.bytes(float(pool.get('usable_free_mb') or 0) * 1024 * 1024)}")
        yield Result(state=State.OK, notice=f"Size on disk: {render.bytes(float(pool.get('size_on_disk_mb') or 0) * 1024 * 1024)}")
    else:
        yield Result(state=State.OK, notice="No capacity reported (tape, cloud or copy pool)")
    yield Result(state=State.OK, notice=f"Pool type {pool.get('pool_type')}, storage type {pool.get('storage_type')}"
                                        + (", archive storage" if pool.get("archive") else ""))


check_plugin_commvault_rest_storage = CheckPlugin(
    name="commvault_rest_storage",
    service_name="Commvault Storage Pool %s",
    discovery_function=discover_storage,
    check_function=check_storage,
    check_default_parameters=FILESYSTEM_DEFAULT_PARAMS,
    check_ruleset_name="filesystem",
)


# --------------------------------------------------------------------------- VM summary (CommServe host)

def discover_vms(section) -> DiscoveryResult:
    if section:
        yield Service()


def check_vms(params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    d = section.get("data") or {}
    by_sla = d.get("by_sla") or {}
    by_status = d.get("by_status") or {}
    yield Result(state=State.OK, summary=(f"{d.get('hosts', 0)} VMs ({d.get('retired', 0)} retired not counted), "
                                          f"SLA met {by_sla.get('MET_SLA', 0)}, missed {by_sla.get('MISSED_SLA', 0)}, "
                                          f"excluded {by_sla.get('EXCLUDED_SLA', 0)}"))
    problems = d.get("problems") or {}
    for key, param, label in (("MISSED_SLA", "state_missed_sla", "missed SLA"),
                              ("FAILED", "state_failed", "status FAILED"),
                              ("WARNING", "state_warning", "status WARNING")):
        names = problems.get(key) or []
        if names:
            shown = ", ".join(names[:10]) + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
            yield Result(state=State(params.get(param, 0)), summary=f"{len(names)} {label}: {shown}")
    yield Result(state=State.OK, notice="By status: " + ", ".join(f"{k} {v}" for k, v in sorted(by_status.items())))
    if d.get("duplicate_names"):
        yield Result(state=State.OK, notice=f"{d['duplicate_names']} VM name(s) with several Commvault entries "
                                            "(merged for piggyback)")
    yield Metric("commvault_rest_vms", int(d.get("hosts") or 0))
    yield Metric("commvault_rest_vms_missed_sla", int(by_sla.get("MISSED_SLA") or 0))


check_plugin_commvault_rest_vms = CheckPlugin(
    name="commvault_rest_vms",
    service_name="Commvault VMs",
    discovery_function=discover_vms,
    check_function=check_vms,
    check_default_parameters={"state_missed_sla": 1, "state_failed": 1, "state_warning": 0},
    check_ruleset_name="commvault_rest_vms",
)


# --------------------------------------------------------------------------- VM backup (piggyback)

VM_DEFAULTS = {
    "state_sla_met": 0,
    "state_sla_missed": 2,
    "state_sla_excluded": 0,
    "state_protected": 0,
    "state_warning": 1,
    "state_failed": 2,
    "state_not_protected": 1,
    "state_discovered": 1,
    "state_other": 1,
}
VM_STATUS_PARAM = {
    "PROTECTED": "state_protected",
    "WARNING": "state_warning",
    "FAILED": "state_failed",
    "NOT_PROTECTED": "state_not_protected",
    "DISCOVERED": "state_discovered",
}


def discover_vm(section) -> DiscoveryResult:
    if isinstance(section, dict) and isinstance(section.get("data"), dict):
        yield Service()


def check_vm(params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    vm = section.get("data") or {}
    now = time.time()
    sla, reason = vm.get("sla") or "", vm.get("sla_reason") or ""
    excluded = sla == "EXCLUDED_SLA"
    if sla == "MET_SLA":
        yield Result(state=State(params.get("state_sla_met", 0)), summary="SLA met")
    elif sla == "MISSED_SLA":
        yield Result(state=State(params.get("state_sla_missed", 2)), summary=f"SLA missed: {reason}")
    elif excluded:
        yield Result(state=State(params.get("state_sla_excluded", 0)), summary=f"Excluded from SLA: {reason}")
    else:
        yield Result(state=State(params.get("state_other", 1)), summary=f"SLA {sla or 'unknown'}: {reason}")

    status = vm.get("status") or "unknown"
    status_state = State.OK if excluded else State(params.get(VM_STATUS_PARAM.get(status, "state_other"), 1))
    yield Result(state=status_state, summary=f"Status: {status}")

    if vm.get("last_time"):
        text = (f"Last backup: {vm.get('last_status') or 'unknown'} at {render.datetime(vm['last_time'])} "
                f"(job {vm.get('last_job')})")
        yield Result(state=State.OK, summary=text)
    else:
        yield Result(state=State.OK, summary="No backup recorded")
    if vm.get("failure"):
        yield Result(state=State.OK, summary=f"Reason: {_oneline(vm['failure'], 300)}")

    if vm.get("last_success"):
        yield from check_levels(
            _age(vm["last_success"], now),
            levels_upper=None if excluded else _levels(params, "max_age_success"),
            metric_name="commvault_rest_backup_age",
            render_func=render.timespan,
            label="Last successful backup",
        )
    for label, key in (("VM group", "vm_group"), ("Plan", "plan"), ("Hypervisor", "hypervisor"),
                       ("ESX host", "esx_host"), ("UUID", "uuid")):
        if vm.get(key):
            yield Result(state=State.OK, notice=f"{label}: {vm[key]}")
    for dup in vm.get("duplicates") or []:
        yield Result(state=State.OK, notice=(f"Ignored duplicate entry: {dup.get('name')} in VM group "
                                             f"{dup.get('vm_group') or '-'} ({dup.get('status')}, {dup.get('sla')}, "
                                             f"{dup.get('hypervisor')}, UUID {dup.get('uuid')})"))


check_plugin_commvault_rest_vm = CheckPlugin(
    name="commvault_rest_vm",
    service_name="Commvault VM Backup",
    discovery_function=discover_vm,
    check_function=check_vm,
    check_default_parameters=VM_DEFAULTS,
    check_ruleset_name="commvault_rest_vm",
)


# --------------------------------------------------------------------------- MediaAgents

MA_DEFAULTS = {
    "state_offline": 2,
    "state_offline_no_error": 1,
    "state_unlicensed": 1,
    "state_other": 1,
}


def _mediaagents(section) -> dict[str, dict]:
    if not isinstance(section, dict) or not isinstance(section.get("data"), list):
        return {}
    return {m["name"]: m for m in section["data"] if isinstance(m, dict) and m.get("name")}


def discover_mediaagent(section) -> DiscoveryResult:
    for name in _mediaagents(section):
        yield Service(item=name)


def check_mediaagent(item: str, params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    ma = _mediaagents(section).get(item)
    if ma is None:
        return  # vanished from the CommServe: Checkmk shows the service as stale/vanished
    status = (ma.get("status") or "").upper()
    reason = _oneline(ma.get("offline_reason") or "", 300)
    if status == "ONLINE":
        yield Result(state=State.OK, summary="Online")
    elif status == "OFFLINE":
        # offlineReasonValue 0 = "No errors detected" (seen on SP44 for offline MAs with only
        # the base role); 1 = MediaMount Manager not reachable, 2 = version mismatch, ...
        key = "state_offline_no_error" if ma.get("offline_reason_value") == 0 else "state_offline"
        yield Result(state=State(params.get(key, 2)),
                     summary=f"Offline: {reason or 'no reason given'}"
                             + (f" (reason code {ma['offline_reason_value']})"
                                if ma.get("offline_reason_value") is not None else ""))
    else:
        yield Result(state=State(params.get("state_other", 1)),
                     summary=f"Status {ma.get('status') or 'unknown'}" + (f": {reason}" if reason else ""))
    if ma.get("unlicensed"):
        yield Result(state=State(params.get("state_unlicensed", 1)), summary="Unlicensed MediaAgent")
    yield Result(state=State.OK, summary=f"Version {ma.get('version') or '?'}")
    for label, key in (("Description", "description"), ("OS", "os")):
        if ma.get(key):
            yield Result(state=State.OK, notice=f"{label}: {ma[key]}")
    yield _fetched(section, "Status")


check_plugin_commvault_rest_mediaagent = CheckPlugin(
    name="commvault_rest_mediaagent",
    sections=["commvault_rest_mediaagents"],
    service_name="Commvault MediaAgent %s",
    discovery_function=discover_mediaagent,
    check_function=check_mediaagent,
    check_default_parameters=MA_DEFAULTS,
    check_ruleset_name="commvault_rest_mediaagent",
)


# --------------------------------------------------------------------------- License

LICENSE_DEFAULTS = {
    "expiry_levels": ("fixed", (60 * 86400.0, 30 * 86400.0)),
    "state_not_production": 1,
    "state_no_expiry": 1,
    "state_over_capacity_msg": 1,
    "state_grace_period": 1,
}


def discover_license(section_commvault_rest_license, section_commvault_rest_license_usage) -> DiscoveryResult:
    if section_commvault_rest_license:
        yield Service()


def check_license(params, section_commvault_rest_license, section_commvault_rest_license_usage) -> CheckResult:
    section = section_commvault_rest_license
    if (err := _error(section)) is not None:
        yield err
        return
    lic = section.get("data") or {}
    mode = lic.get("mode") or "unknown"
    yield Result(state=State.OK if mode.upper() == "PRODUCTION" else State(params.get("state_not_production", 1)),
                 summary=f"Mode {mode}")
    expiry = lic.get("expiry")
    if expiry:
        remaining = float(expiry) - time.time()
        yield Result(state=State.OK, summary=f"Expires {render.date(float(expiry))}")
        if remaining <= 0:
            yield Result(state=State.CRIT, summary=f"Expired {render.timespan(-remaining)} ago")
        else:
            yield from check_levels(remaining, levels_lower=_levels(params, "expiry_levels"),
                                    render_func=render.timespan, label="Remaining",
                                    metric_name="commvault_rest_license_remaining")
    else:
        yield Result(state=State(params.get("state_no_expiry", 1)), summary="No expiry date reported")
    if lic.get("edition"):
        yield Result(state=State.OK, notice=f"Edition: {lic['edition']}")
    yield _fetched(section, "License information")

    usage = section_commvault_rest_license_usage
    if isinstance(usage, dict) and "error" in usage:
        yield Result(state=State.WARN, summary=f"License usage: API error: {usage['error']}")
    elif isinstance(usage, dict):
        for group, info in sorted(((usage.get("data") or {}).get("groups") or {}).items()):
            if info.get("over_capacity_msg"):
                yield Result(state=State(params.get("state_over_capacity_msg", 1)),
                             summary=f"CommServe reports over capacity ({group} licensing)")
            if info.get("grace_period"):
                yield Result(state=State(params.get("state_grace_period", 1)),
                             summary=f"Grace period active ({group} licensing): {info['grace_period']}")
            if info.get("ip_valid") is False:
                yield Result(state=State.WARN, summary=f"License IP not valid ({group} licensing)")


check_plugin_commvault_rest_license = CheckPlugin(
    name="commvault_rest_license",
    sections=["commvault_rest_license", "commvault_rest_license_usage"],
    service_name="Commvault License",
    discovery_function=discover_license,
    check_function=check_license,
    check_default_parameters=LICENSE_DEFAULTS,
    check_ruleset_name="commvault_rest_license",
)


LICENSE_USAGE_DEFAULTS = {
    "usage_levels": ("fixed", (90.0, 95.0)),
    "state_expired": 2,
}


def _license_types(section) -> dict[str, dict]:
    if not isinstance(section, dict) or not isinstance(section.get("data"), dict):
        return {}
    types = [t for t in section["data"].get("types") or [] if isinstance(t, dict) and t.get("name")]
    names = [t["name"] for t in types]
    out = {}
    for t in types:
        item = t["name"] if names.count(t["name"]) == 1 else f"{t['name']} ({t.get('group')})"
        out[item] = t
    return out


def discover_license_usage(section) -> DiscoveryResult:
    for item, t in _license_types(section).items():
        # Types without any purchased or used amount are not part of the contract
        if t.get("total") or t.get("used") or t.get("expired"):
            yield Service(item=item)


def check_license_usage(item: str, params, section) -> CheckResult:
    if (err := _error(section)) is not None:
        yield err
        return
    t = _license_types(section).get(item)
    if t is None:
        return
    used, total = int(t.get("used") or 0), int(t.get("total") or 0)
    if t.get("expired"):
        yield Result(state=State(params.get("state_expired", 2)), summary="License expired")
    if total > 0:
        yield Result(state=State.OK, summary=f"Used {used} of {total}")
        yield from check_levels(used * 100.0 / total, levels_upper=_levels(params, "usage_levels"),
                                render_func=render.percent, label="Usage",
                                metric_name="commvault_rest_license_usage", boundaries=(0.0, None))
    else:
        yield Result(state=State.WARN, summary=f"Used {used}, but no licensed amount reported")
    yield Metric("commvault_rest_license_used", float(used))
    yield Metric("commvault_rest_license_total", float(total))
    yield Result(state=State.OK, notice="Unit as defined by Commvault for this license type "
                                        "(not reported by the API)")
    yield Result(state=State.OK, notice=(f"Licensing: {t.get('group')}, evaluation flag: "
                                         f"{'yes' if t.get('evaluation') else 'no'}, applied flag: "
                                         f"{'yes' if t.get('applied') else 'no'}, license ID {t.get('id')}"))
    yield _fetched(section, "Usage")


check_plugin_commvault_rest_license_usage = CheckPlugin(
    name="commvault_rest_license_usage",
    service_name="Commvault License %s",
    discovery_function=discover_license_usage,
    check_function=check_license_usage,
    check_default_parameters=LICENSE_USAGE_DEFAULTS,
    check_ruleset_name="commvault_rest_license_usage",
)
