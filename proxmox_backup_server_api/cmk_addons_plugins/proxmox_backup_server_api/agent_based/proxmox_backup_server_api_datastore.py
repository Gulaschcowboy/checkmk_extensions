#!/usr/bin/env python3
"""PBS datastore check — one service per datastore (usage + estimated full)."""
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


def parse_proxmox_backup_server_api_datastore(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_proxmox_backup_server_api_datastore = AgentSection(
    name="proxmox_backup_server_api_datastore",
    parse_function=parse_proxmox_backup_server_api_datastore,
)


def discover_proxmox_backup_server_api_datastore(section):
    if "_error" in section:
        return
    for name in section:
        yield Service(item=name)


def check_proxmox_backup_server_api_datastore(item, params, section):
    if "_error" in section:
        yield Result(state=State.UNKNOWN, summary="API error: %s" % section["_error"])
        return
    ds = section.get(item)
    if ds is None:
        yield Result(state=State.UNKNOWN, summary="Datastore not found in API output")
        return

    if ds.get("_status_error"):
        yield Result(state=State.UNKNOWN,
                     summary="Datastore status error: %s" % ds["_status_error"])

    maint = ds.get("maintenance")
    if maint:
        yield Result(state=State.WARN, summary="Maintenance mode: %s" % maint)

    mount = ds.get("mount_status")
    if mount and mount not in ("nonremovable", "mounted"):
        yield Result(state=State.WARN, summary="Mount status: %s" % mount)

    total = ds.get("total")
    used = ds.get("used")
    if total and used is not None:
        try:
            total = int(total)
            used = int(used)
        except (ValueError, TypeError):
            total = None
    if total and total > 0:
        pct = 100.0 * used / total
        warn, crit = params.get("levels", (80.0, 90.0))
        state = State.OK
        if pct >= crit:
            state = State.CRIT
        elif pct >= warn:
            state = State.WARN
        yield Result(state=state,
                     summary="Used: %s of %s (%.1f%%)"
                     % (render.bytes(used), render.bytes(total), pct))
        yield Metric("fs_used", used,
                     levels=(total * warn / 100, total * crit / 100),
                     boundaries=(0, total))
        yield Metric("fs_used_percent", pct, levels=(warn, crit), boundaries=(0, 100))
        avail = ds.get("avail")
        if avail is not None:
            yield Metric("fs_free", int(avail), boundaries=(0, total))
    else:
        yield Result(state=State.UNKNOWN, summary="No usage data for datastore")

    efd = ds.get("estimated_full_date")
    if efd:
        try:
            efd = int(efd)
        except (ValueError, TypeError):
            efd = None
    if efd and efd > 0:
        remaining = efd - time.time()
        if remaining > 0:
            warn_days, crit_days = params.get("full_horizon_days", (30, 7))
            state = State.OK
            if remaining < crit_days * 86400:
                state = State.CRIT
            elif remaining < warn_days * 86400:
                state = State.WARN
            yield Result(state=state,
                         summary="Estimated full in %s" % render.timespan(remaining))
        else:
            yield Result(state=State.CRIT, summary="Estimated full date has passed")

    if ds.get("comment"):
        yield Result(state=State.OK, notice="Comment: %s" % ds["comment"])


check_plugin_proxmox_backup_server_api_datastore = CheckPlugin(
    name="proxmox_backup_server_api_datastore",
    service_name="PBS Datastore %s",
    discovery_function=discover_proxmox_backup_server_api_datastore,
    check_function=check_proxmox_backup_server_api_datastore,
    check_default_parameters={"levels": (80.0, 90.0), "full_horizon_days": (30, 7)},
    check_ruleset_name="proxmox_backup_server_api_datastore",
)
