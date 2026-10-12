#!/usr/bin/env python3
"""XenServer / XCP-ng: pool, shared storage repositories and alerts.

Sections (written by agent_xenserver, one JSON document per line):
  xenserver_pool    pool overview incl. all members (on the pool host)
  xenserver_srs     storage repositories; shared SRs on the pool host,
                    local SRs in the piggyback data of their XenServer host
  xenserver_alerts  XAPI messages of the last N hours
"""
import re
import time

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

from cmk_addons.plugins.xenserver.lib.xenserver import check_disk_io, json_lines


def parse_xenserver_single(string_table: StringTable):
    docs = json_lines(string_table)
    return docs[0] if docs else None


def parse_xenserver_srs(string_table: StringTable):
    return {sr["name"]: sr for sr in json_lines(string_table) if sr.get("name")}


agent_section_xenserver_pool = AgentSection(name="xenserver_pool", parse_function=parse_xenserver_single)
agent_section_xenserver_alerts = AgentSection(name="xenserver_alerts", parse_function=parse_xenserver_single)
agent_section_xenserver_srs = AgentSection(name="xenserver_srs", parse_function=parse_xenserver_srs)


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------
def discover_xenserver_pool(section) -> DiscoveryResult:
    if section:
        yield Service()


def check_xenserver_pool(params, section) -> CheckResult:
    if not section:
        return
    hosts = section.get("hosts", [])
    yield Result(state=State.OK, summary="Pool %s, %d host(s), coordinator %s" % (
        section.get("name"), len(hosts), section.get("coordinator")))
    for h in hosts:
        if h.get("live") is False:
            yield Result(state=State.CRIT, summary="Host %s is not live" % h["name"])
        if not h.get("enabled"):
            yield Result(state=State(params["state_host_disabled"]),
                         summary="Host %s is disabled (maintenance mode)" % h["name"])
        if h.get("rrd_error"):
            yield Result(state=State(params["state_rrd_error"]),
                         summary="No performance data from host %s" % h["name"],
                         details="RRD error on %s: %s" % (h["name"], h["rrd_error"]))
        yield Result(state=State.OK, notice="%s (%s): %s, %s, %d running VMs%s" % (
            h["name"], h.get("address"), "live" if h.get("live") else "not live",
            "enabled" if h.get("enabled") else "disabled", h.get("running_vms", 0),
            ", coordinator" if h.get("coordinator") else ""))

    if section.get("ha_enabled"):
        tolerate = section.get("ha_host_failures_to_tolerate", 0)
        plan = section.get("ha_plan_exists_for", 0)
        text = "HA enabled, failures to tolerate: %d, plan exists for: %d" % (tolerate, plan)
        if section.get("ha_overcommitted") or plan < tolerate:
            yield Result(state=State(params["state_ha_overcommitted"]), summary=text + " (overcommitted)")
        else:
            yield Result(state=State.OK, summary=text)
    else:
        yield Result(state=State.OK, notice="HA disabled")

    yield Result(state=State.OK, summary="VMs running: %d/%d" % (
        section.get("vms_running", 0), section.get("vms_total", 0)))
    yield Metric("xenserver_vms_running", section.get("vms_running", 0))

    if section.get("connect_errors"):
        yield Result(state=State(params["state_failover"]),
                     summary="Connected via failover address %s" % section.get("connected_to"),
                     details="Unreachable: %s" % "; ".join(section["connect_errors"]))
    for err in section.get("errors", []):
        yield Result(state=State.WARN, notice="Agent: %s" % err)
    yield Result(state=State.OK, notice="Agent version %s" % section.get("agent_version"))


check_plugin_xenserver_pool = CheckPlugin(
    name="xenserver_pool",
    service_name="XenServer Pool",
    discovery_function=discover_xenserver_pool,
    check_function=check_xenserver_pool,
    check_default_parameters={
        "state_host_disabled": 1,
        "state_rrd_error": 1,
        "state_failover": 1,
        "state_ha_overcommitted": 1,
    },
    check_ruleset_name="xenserver_pool",
)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
PRIO_TEXT = {1: "data loss imminent", 2: "service loss imminent", 3: "service degraded",
             4: "service recovered", 5: "informational"}


def discover_xenserver_alerts(section) -> DiscoveryResult:
    if section and section.get("enabled"):
        yield Service()


def check_xenserver_alerts(params, section) -> CheckResult:
    if not section:
        return
    ignore = [re.compile(p) for p in params.get("ignore", [])]
    worst = State.OK
    relevant = []
    for msg in section.get("messages", []):
        if any(rx.search(msg.get("name") or "") or rx.search(msg.get("body") or "") for rx in ignore):
            continue
        state = State(params.get("prio_%d" % msg["priority"], 0))
        relevant.append((state, msg))
        worst = State.worst(worst, state)
    counts = section.get("counts", {})
    total = sum(counts.values())
    if relevant:
        names = {}
        for state, msg in relevant:
            if state != State.OK:
                names[msg["name"]] = names.get(msg["name"], 0) + 1
        summary = "%d alert(s) with priority 1-4 in the last %dh" % (len(relevant), section["window_hours"])
        if names:
            summary += ": " + ", ".join("%s (%d)" % kv for kv in sorted(names.items()))
        yield Result(state=worst, summary=summary)
        for state, msg in relevant[:30]:
            yield Result(state=State.OK, notice="%s [prio %d, %s] %s on %s: %s" % (
                render.datetime(msg["time"]) if msg.get("time") else "?", msg["priority"],
                PRIO_TEXT.get(msg["priority"], "?"), msg["name"], msg.get("object"), msg.get("body", "")))
    else:
        yield Result(state=State.OK, summary="No alerts with priority 1-4 in the last %dh" % section["window_hours"])
    yield Result(state=State.OK, summary="%d messages total" % total,
                 details="Messages per priority: " + ", ".join(
                     "%s: %d" % (p, counts[p]) for p in sorted(counts)))


check_plugin_xenserver_alerts = CheckPlugin(
    name="xenserver_alerts",
    service_name="XenServer Alerts",
    discovery_function=discover_xenserver_alerts,
    check_function=check_xenserver_alerts,
    check_default_parameters={"prio_1": 2, "prio_2": 2, "prio_3": 1, "prio_4": 0, "ignore": []},
    check_ruleset_name="xenserver_alerts",
)


# ---------------------------------------------------------------------------
# Storage repositories
# ---------------------------------------------------------------------------
def discover_xenserver_sr(section) -> DiscoveryResult:
    for name, sr in section.items():
        if sr.get("size"):
            yield Service(item=name)


def check_xenserver_sr(item, params, section) -> CheckResult:
    sr = section.get(item)
    if sr is None:
        return
    mib = 1024.0 * 1024.0
    size = sr["size"] / mib
    free = max(sr["size"] - sr["used"], 0) / mib
    yield from df_check_filesystem_single(get_value_store(), item, size, free, 0, None, None,
                                          params, this_time=time.time())
    yield Result(state=State.OK, summary="Type: %s%s" % (sr.get("type"), ", shared" if sr.get("shared") else ""))
    if sr.get("size") and sr.get("allocated"):
        yield Result(state=State.OK, notice="Provisioned: %s (%s of the size)" % (
            render.bytes(sr["allocated"]), render.percent(100.0 * sr["allocated"] / sr["size"])))
    for pbd in sr.get("pbds", []):
        if not pbd.get("attached"):
            yield Result(state=State.CRIT, summary="Not attached on host %s" % pbd["host"])
        for dev, (active, total) in pbd.get("mpath", {}).items():
            text = "Multipath %s on %s: %d/%d paths active" % (dev, pbd["host"], active, total)
            if active == 0:
                yield Result(state=State.CRIT, summary=text)
            elif active < total:
                yield Result(state=State.WARN, summary=text)
            else:
                yield Result(state=State.OK, notice=text)


check_plugin_xenserver_sr = CheckPlugin(
    name="xenserver_sr",
    sections=["xenserver_srs"],
    service_name="XenServer SR %s",
    discovery_function=discover_xenserver_sr,
    check_function=check_xenserver_sr,
    check_default_parameters=FILESYSTEM_DEFAULT_PARAMS,
    check_ruleset_name="filesystem",
)


def discover_xenserver_sr_io(section) -> DiscoveryResult:
    for name, sr in section.items():
        if sr.get("io"):
            yield Service(item=name)


def check_xenserver_sr_io(item, params, section) -> CheckResult:
    sr = section.get(item)
    if sr is None:
        return
    if not sr.get("io"):
        yield Result(state=State.OK, summary="No I/O data available")
        return
    yield from check_disk_io(params, sr["io"])


check_plugin_xenserver_sr_io = CheckPlugin(
    name="xenserver_sr_io",
    sections=["xenserver_srs"],
    service_name="XenServer SR I/O %s",
    discovery_function=discover_xenserver_sr_io,
    check_function=check_xenserver_sr_io,
    check_default_parameters={},
    check_ruleset_name="xenserver_disk_io",
)
