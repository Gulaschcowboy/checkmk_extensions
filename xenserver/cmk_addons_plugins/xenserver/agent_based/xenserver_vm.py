#!/usr/bin/env python3
"""XenServer / XCP-ng VM checks (piggyback data of agent_xenserver, one host per VM)."""
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
    render,
)

from cmk_addons.plugins.xenserver.lib.xenserver import check_disk_io, json_lines


def parse_xenserver_vm(string_table: StringTable):
    docs = json_lines(string_table)
    return docs[0] if docs else None


agent_section_xenserver_vm = AgentSection(name="xenserver_vm", parse_function=parse_xenserver_vm)


def _running(section) -> bool:
    return section.get("power_state") == "Running"


def _discover_single(section) -> DiscoveryResult:
    if section:
        yield Service()


# ---------------------------------------------------------------------------
# VM state
# ---------------------------------------------------------------------------
POWER_STATES = ("Running", "Halted", "Paused", "Suspended")


def check_xenserver_vm(params, section) -> CheckResult:
    if not section:
        return
    power = section.get("power_state") or "unknown"
    state = State(params.get("state_%s" % power.lower(), 3))
    text = "Power state: %s" % power
    if power == "Running" and section.get("host"):
        text += " on %s" % section["host"]
    yield Result(state=state, summary=text)
    if _running(section) and section.get("start_time"):
        yield from check_levels(time.time() - section["start_time"], metric_name="uptime",
                                label="Uptime", render_func=render.timespan)
    yield Result(state=State.OK, summary="%s vCPU, %s RAM" % (
        section.get("vcpus"), render.bytes(section.get("memory_static_max") or 0)))
    if section.get("os_name"):
        yield Result(state=State.OK, summary="OS: %s" % section["os_name"])
    if section.get("ips"):
        yield Result(state=State.OK, notice="IP addresses: %s" % ", ".join(section["ips"]))
    if section.get("requires_reboot"):
        yield Result(state=State(params["state_requires_reboot"]),
                     summary="Reboot required to apply configuration changes")
    if section.get("affinity") and _running(section) and section.get("host") != section["affinity"]:
        yield Result(state=State.OK, notice="Not running on its home server %s" % section["affinity"])
    if section.get("ha_restart_priority"):
        yield Result(state=State.OK, notice="HA restart priority: %s" % section["ha_restart_priority"])
    if section.get("tags"):
        yield Result(state=State.OK, notice="Tags: %s" % ", ".join(section["tags"]))
    yield Result(state=State.OK, notice="Pool: %s, UUID: %s" % (section.get("pool"), section.get("uuid")))


check_plugin_xenserver_vm = CheckPlugin(
    name="xenserver_vm",
    service_name="XenServer VM",
    discovery_function=_discover_single,
    check_function=check_xenserver_vm,
    check_default_parameters={"state_running": 0, "state_halted": 0, "state_paused": 1,
                              "state_suspended": 0, "state_requires_reboot": 0},
    check_ruleset_name="xenserver_vm_state",
)


# ---------------------------------------------------------------------------
# CPU / memory
# ---------------------------------------------------------------------------
def check_xenserver_vm_cpu(params, section) -> CheckResult:
    if not section:
        return
    if not _running(section):
        yield Result(state=State.OK, summary="VM is not running (%s)" % section.get("power_state"))
        return
    cpu = section.get("rrd", {}).get("cpu")
    if cpu is None:
        yield Result(state=State.UNKNOWN, summary="No CPU data (RRD not available)")
        return
    yield from check_levels(cpu * 100.0, levels_upper=params.get("levels"), metric_name="util",
                            label="CPU utilization (%s vCPU)" % section.get("vcpus"),
                            render_func=render.percent, boundaries=(0.0, 100.0))


check_plugin_xenserver_vm_cpu = CheckPlugin(
    name="xenserver_vm_cpu",
    sections=["xenserver_vm"],
    service_name="XenServer VM CPU",
    discovery_function=_discover_single,
    check_function=check_xenserver_vm_cpu,
    check_default_parameters={},
    check_ruleset_name="xenserver_cpu",
)


def check_xenserver_vm_mem(params, section) -> CheckResult:
    if not section:
        return
    if not _running(section):
        yield Result(state=State.OK, summary="VM is not running (%s)" % section.get("power_state"))
        return
    rrd = section.get("rrd", {})
    assigned = rrd.get("memory") or section.get("memory_target") or section.get("memory_static_max")
    if not assigned:
        yield Result(state=State.UNKNOWN, summary="No memory data")
        return
    yield Result(state=State.OK, summary="Assigned: %s" % render.bytes(assigned))
    free_kib = rrd.get("memory_internal_free_kib")
    if free_kib is None:
        yield Result(state=State.OK, summary="In-guest usage not available (guest tools required)")
        return
    used = max(assigned - free_kib * 1024.0, 0.0)
    yield from check_levels(100.0 * used / assigned, levels_upper=params.get("levels"),
                            metric_name="mem_used_percent", render_func=render.percent,
                            label="Used in guest: %s" % render.bytes(used), boundaries=(0.0, 100.0))
    yield Metric("mem_used", used, boundaries=(0, assigned))
    yield Metric("mem_total", assigned)
    if section.get("memory_dynamic_min") != section.get("memory_dynamic_max"):
        yield Result(state=State.OK, notice="Dynamic memory: %s - %s" % (
            render.bytes(section.get("memory_dynamic_min") or 0),
            render.bytes(section.get("memory_dynamic_max") or 0)))


check_plugin_xenserver_vm_mem = CheckPlugin(
    name="xenserver_vm_mem",
    sections=["xenserver_vm"],
    service_name="XenServer VM Memory",
    discovery_function=_discover_single,
    check_function=check_xenserver_vm_mem,
    check_default_parameters={},
    check_ruleset_name="xenserver_memory",
)


# ---------------------------------------------------------------------------
# Disks / interfaces
# ---------------------------------------------------------------------------
def discover_xenserver_vm_disk(section) -> DiscoveryResult:
    if not section:
        return
    for vbd in section.get("vbds", []):
        if vbd.get("device"):
            yield Service(item=vbd["device"])


def check_xenserver_vm_disk(item, params, section) -> CheckResult:
    if not section:
        return
    vbd = next((b for b in section.get("vbds", []) if b.get("device") == item), None)
    if vbd is None:
        return
    yield Result(state=State.OK, summary="%s on SR %s, %s" % (
        vbd.get("vdi"), vbd.get("sr"), render.bytes(vbd.get("size") or 0)))
    if not _running(section):
        yield Result(state=State.OK, summary="VM is not running")
        return
    if not vbd.get("attached"):
        yield Result(state=State.WARN, summary="Disk is not attached")
    yield from check_disk_io(params, vbd)


check_plugin_xenserver_vm_disk = CheckPlugin(
    name="xenserver_vm_disk",
    sections=["xenserver_vm"],
    service_name="XenServer VM Disk %s",
    discovery_function=discover_xenserver_vm_disk,
    check_function=check_xenserver_vm_disk,
    check_default_parameters={},
    check_ruleset_name="xenserver_disk_io",
)


def discover_xenserver_vm_if(section) -> DiscoveryResult:
    if not section:
        return
    for vif in section.get("vifs", []):
        if vif.get("device") is not None:
            yield Service(item=str(vif["device"]))


def check_xenserver_vm_if(item, section) -> CheckResult:
    if not section:
        return
    vif = next((i for i in section.get("vifs", []) if str(i.get("device")) == item), None)
    if vif is None:
        return
    yield Result(state=State.OK, summary="Network: %s, MAC: %s" % (vif.get("network"), vif.get("mac")))
    if not _running(section):
        yield Result(state=State.OK, summary="VM is not running")
        return
    if not vif.get("attached"):
        yield Result(state=State.WARN, summary="Interface is not attached")
    for key, metric, label in (("rx", "if_in_bps", "In"), ("tx", "if_out_bps", "Out")):
        if vif.get(key) is not None:
            yield from check_levels(vif[key] * 8, metric_name=metric, label=label,
                                    render_func=render.networkbandwidth)


check_plugin_xenserver_vm_if = CheckPlugin(
    name="xenserver_vm_if",
    sections=["xenserver_vm"],
    service_name="XenServer VM Interface %s",
    discovery_function=discover_xenserver_vm_if,
    check_function=check_xenserver_vm_if,
)


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------
def check_xenserver_vm_snapshots(params, section) -> CheckResult:
    if not section:
        return
    snaps = [s for s in section.get("snapshots", []) if s.get("time")]
    yield from check_levels(len(snaps), levels_upper=params.get("count"),
                            metric_name="xenserver_snapshot_count", label="Snapshots",
                            render_func=lambda v: "%d" % v)
    if section.get("vmss"):
        yield Result(state=State.OK, summary="Schedule: %s" % section["vmss"])
    if not snaps:
        return
    oldest = min(snaps, key=lambda s: s["time"])
    newest = max(snaps, key=lambda s: s["time"])
    now = time.time()
    yield from check_levels(max(now - oldest["time"], 0), levels_upper=params.get("age_oldest"),
                            metric_name="xenserver_snapshot_age", label="Oldest (%s)" % oldest["name"],
                            render_func=render.timespan)
    yield Result(state=State.OK, summary="Newest: %s (%s ago)" % (
        newest["name"], render.timespan(max(now - newest["time"], 0))))
    for s in sorted(snaps, key=lambda s: s["time"]):
        yield Result(state=State.OK, notice="%s: %s" % (render.datetime(s["time"]), s["name"]))


check_plugin_xenserver_vm_snapshots = CheckPlugin(
    name="xenserver_vm_snapshots",
    sections=["xenserver_vm"],
    service_name="XenServer VM Snapshots",
    discovery_function=_discover_single,
    check_function=check_xenserver_vm_snapshots,
    check_default_parameters={"age_oldest": ("fixed", (7 * 86400.0, 30 * 86400.0))},
    check_ruleset_name="xenserver_snapshots",
)


# ---------------------------------------------------------------------------
# Guest tools
# ---------------------------------------------------------------------------
def check_xenserver_vm_tools(params, section) -> CheckResult:
    if not section:
        return
    if not _running(section):
        yield Result(state=State.OK, summary="VM is not running (%s)" % section.get("power_state"))
        return
    if not section.get("guest_metrics"):
        yield Result(state=State(params["state_missing"]),
                     summary="No guest metrics, guest tools not installed or not running")
        return
    if section.get("pv_drivers_detected") is False:
        yield Result(state=State(params["state_missing"]), summary="PV drivers not detected")
    else:
        yield Result(state=State.OK, summary="Guest agent reporting")
    if section.get("pv_drivers_version"):
        yield Result(state=State.OK, summary="Version: %s" % section["pv_drivers_version"])
    if section.get("pv_drivers_up_to_date") is False:
        yield Result(state=State(params["state_outdated"]), summary="PV drivers out of date")
    if section.get("guest_last_updated"):
        yield Result(state=State.OK, notice="Guest metrics last updated: %s" %
                     render.datetime(section["guest_last_updated"]))


check_plugin_xenserver_vm_tools = CheckPlugin(
    name="xenserver_vm_tools",
    sections=["xenserver_vm"],
    service_name="XenServer VM Guest Tools",
    discovery_function=_discover_single,
    check_function=check_xenserver_vm_tools,
    check_default_parameters={"state_missing": 1, "state_outdated": 0},
    check_ruleset_name="xenserver_guest_tools",
)
