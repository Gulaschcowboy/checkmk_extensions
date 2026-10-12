#!/usr/bin/env python3
"""XenServer / XCP-ng host checks (piggyback data of agent_xenserver).

Service names carry the prefix "XenServer" so they do not collide with
services of a Checkmk agent installed in dom0.
"""
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

from cmk_addons.plugins.xenserver.lib.xenserver import json_lines


def parse_xenserver_host(string_table: StringTable):
    docs = json_lines(string_table)
    return docs[0] if docs else None


agent_section_xenserver_host = AgentSection(name="xenserver_host", parse_function=parse_xenserver_host)


def _discover_single(section) -> DiscoveryResult:
    if section:
        yield Service()


# ---------------------------------------------------------------------------
# Host overview
# ---------------------------------------------------------------------------
def check_xenserver_host(params, section) -> CheckResult:
    if not section:
        return
    yield Result(state=State.OK, summary="%s (build %s, xapi %s)" % (
        section.get("product"), section.get("build"), section.get("xapi")))
    role = "coordinator" if section.get("coordinator") else "member"
    yield Result(state=State.OK, summary="%s of pool %s" % (role.capitalize(), section.get("pool")))
    if section.get("live") is False:
        yield Result(state=State.CRIT, summary="Host is not live")
    if not section.get("enabled"):
        yield Result(state=State(params["state_disabled"]), summary="Host is disabled (maintenance mode)")
    yield Result(state=State.OK, summary="Running VMs: %d" % section.get("running_vms", 0))
    yield Metric("xenserver_vms_running", section.get("running_vms", 0))
    if section.get("boot_time"):
        uptime = time.time() - section["boot_time"]
        yield from check_levels(uptime, metric_name="uptime", label="Up since %s, uptime" %
                                render.datetime(section["boot_time"]), render_func=render.timespan)
    if section.get("clock_offset") is not None:
        offset = section["clock_offset"]
        yield from check_levels(abs(offset), levels_upper=params.get("clock_offset"),
                                label="Clock offset to Checkmk server (%s)" % (
                                    "ahead" if offset >= 0 else "behind"),
                                render_func=lambda v: "%.1f s" % v)
        yield Metric("time_offset", offset)
    if section.get("rrd_error"):
        yield Result(state=State.WARN, summary="No performance data (RRD)",
                     details=section["rrd_error"])
    yield Result(state=State.OK, notice="CPU: %s x %s" % (section.get("cpu_count"), section.get("cpu_model")))
    yield Result(state=State.OK, notice="Address: %s, hostname: %s, UUID: %s" % (
        section.get("address"), section.get("hostname"), section.get("uuid")))
    if section.get("rrd", {}).get("power") is not None:
        yield Metric("power", section["rrd"]["power"])
        yield Result(state=State.OK, notice="Power consumption: %.0f W" % section["rrd"]["power"])


check_plugin_xenserver_host = CheckPlugin(
    name="xenserver_host",
    service_name="XenServer Host",
    discovery_function=_discover_single,
    check_function=check_xenserver_host,
    check_default_parameters={"state_disabled": 1, "clock_offset": ("fixed", (30.0, 60.0))},
    check_ruleset_name="xenserver_host",
)


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------
def discover_xenserver_host_cpu(section) -> DiscoveryResult:
    if section and section.get("rrd", {}).get("cpu_avg") is not None:
        yield Service()


def check_xenserver_host_cpu(params, section) -> CheckResult:
    if not section:
        return
    rrd = section.get("rrd", {})
    if rrd.get("cpu_avg") is None:
        yield Result(state=State.UNKNOWN, summary="No CPU data (RRD not available)")
        return
    yield from check_levels(rrd["cpu_avg"] * 100.0, levels_upper=params.get("levels"),
                            metric_name="util", label="Total CPU", render_func=render.percent,
                            boundaries=(0.0, 100.0))
    if rrd.get("loadavg") is not None:
        yield from check_levels(rrd["loadavg"], metric_name="load1", label="Load (dom0)",
                                render_func=lambda v: "%.2f" % v, notice_only=True)
    if rrd.get("running_vcpus") is not None:
        yield Result(state=State.OK, summary="Running vCPUs: %.0f on %s physical CPUs" % (
            rrd["running_vcpus"], rrd.get("cpus") or section.get("cpu_count")))


check_plugin_xenserver_host_cpu = CheckPlugin(
    name="xenserver_host_cpu",
    sections=["xenserver_host"],
    service_name="XenServer Host CPU",
    discovery_function=discover_xenserver_host_cpu,
    check_function=check_xenserver_host_cpu,
    check_default_parameters={"levels": ("fixed", (90.0, 95.0))},
    check_ruleset_name="xenserver_cpu",
)


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------
def _host_memory(section):
    rrd = section.get("rrd", {})
    if rrd.get("memory_total_kib") and rrd.get("memory_free_kib") is not None:
        return rrd["memory_total_kib"] * 1024.0, rrd["memory_free_kib"] * 1024.0
    if section.get("memory_total"):
        return float(section["memory_total"]), float(section.get("memory_free") or 0)
    return None


def discover_xenserver_host_mem(section) -> DiscoveryResult:
    if section and _host_memory(section):
        yield Service()


def check_xenserver_host_mem(params, section) -> CheckResult:
    if not section:
        return
    mem = _host_memory(section)
    if not mem:
        return
    total, free = mem
    used = total - free
    yield from check_levels(100.0 * used / total, levels_upper=params.get("levels"),
                            metric_name="mem_used_percent", render_func=render.percent,
                            label="Used: %s of %s" % (render.bytes(used), render.bytes(total)),
                            boundaries=(0.0, 100.0))
    yield Metric("mem_used", used, boundaries=(0, total))
    yield Metric("mem_total", total)
    yield Result(state=State.OK, notice="Free for new VMs: %s" % render.bytes(free))


check_plugin_xenserver_host_mem = CheckPlugin(
    name="xenserver_host_mem",
    sections=["xenserver_host"],
    service_name="XenServer Host Memory",
    discovery_function=discover_xenserver_host_mem,
    check_function=check_xenserver_host_mem,
    check_default_parameters={},
    check_ruleset_name="xenserver_memory",
)


# ---------------------------------------------------------------------------
# Physical interfaces / bonds
# ---------------------------------------------------------------------------
def discover_xenserver_host_if(section) -> DiscoveryResult:
    if not section:
        return
    for pif in section.get("pifs", []):
        if pif.get("carrier") or pif.get("attached") or pif.get("bond_slave"):
            yield Service(item=pif["device"])


def check_xenserver_host_if(item, section) -> CheckResult:
    if not section:
        return
    pif = next((p for p in section.get("pifs", []) if p["device"] == item), None)
    if pif is None:
        return
    kind = "Bond" if pif.get("bond") else "Bond member" if pif.get("bond_slave") else "NIC"
    if pif.get("carrier") is False:
        yield Result(state=State.CRIT, summary="Link down")
    else:
        yield Result(state=State.OK, summary="Link up")
    if pif.get("speed_mbit"):
        yield Result(state=State.OK, summary="Speed: %s" % render.nicspeed(pif["speed_mbit"] * 1e6 / 8))
    yield Result(state=State.OK, summary="%s%s, network: %s" % (
        kind, ", management" if pif.get("management") else "", pif.get("network")))
    if not pif.get("attached") and not pif.get("bond_slave"):
        yield Result(state=State.OK, notice="Not attached (not plugged)")
    for key, metric, label in (("rx", "if_in_bps", "In"), ("tx", "if_out_bps", "Out")):
        if pif.get(key) is not None:
            yield from check_levels(pif[key] * 8, metric_name=metric, label=label,
                                    render_func=render.networkbandwidth)
    yield Result(state=State.OK, notice="MAC: %s, device: %s %s" % (
        pif.get("mac"), pif.get("vendor") or "", pif.get("device_name") or ""))


check_plugin_xenserver_host_if = CheckPlugin(
    name="xenserver_host_if",
    sections=["xenserver_host"],
    service_name="XenServer Interface %s",
    discovery_function=discover_xenserver_host_if,
    check_function=check_xenserver_host_if,
)


# ---------------------------------------------------------------------------
# License / certificates
# ---------------------------------------------------------------------------
def _check_expiry(expiry, params, label):
    remaining = expiry - time.time()
    if remaining <= 0:
        yield Result(state=State.CRIT, summary="%s expired %s ago (%s)" % (
            label, render.timespan(-remaining), render.date(expiry)))
        return
    yield from check_levels(remaining, levels_lower=params.get("levels"),
                            label="%s expires %s, remaining" % (label, render.date(expiry)),
                            render_func=render.timespan)


def check_xenserver_license(params, section) -> CheckResult:
    if not section:
        return
    yield Result(state=State.OK, summary="Edition: %s" % section.get("edition"))
    if section.get("license_expiry"):
        yield from _check_expiry(section["license_expiry"], params, "License")
    else:
        yield Result(state=State.OK, summary="No license expiry")
    if section.get("css_expiry"):
        yield Result(state=State.OK, notice="Customer Success Services expiry: %s" % section["css_expiry"])


check_plugin_xenserver_license = CheckPlugin(
    name="xenserver_license",
    sections=["xenserver_host"],
    service_name="XenServer License",
    discovery_function=_discover_single,
    check_function=check_xenserver_license,
    check_default_parameters={"levels": ("fixed", (30 * 86400.0, 14 * 86400.0))},
    check_ruleset_name="xenserver_license",
)


def _cert_item(cert):
    return ("%s %s" % (cert.get("type"), cert.get("name"))).strip()


def discover_xenserver_cert(section) -> DiscoveryResult:
    if not section:
        return
    for cert in section.get("certificates", []):
        if cert.get("not_after"):
            yield Service(item=_cert_item(cert))


def check_xenserver_cert(item, params, section) -> CheckResult:
    if not section:
        return
    cert = next((c for c in section.get("certificates", []) if _cert_item(c) == item), None)
    if cert is None:
        return
    yield from _check_expiry(cert["not_after"], params, "Certificate")
    yield Result(state=State.OK, notice="Fingerprint (SHA256): %s..." % cert.get("fingerprint"))


check_plugin_xenserver_cert = CheckPlugin(
    name="xenserver_cert",
    sections=["xenserver_host"],
    service_name="XenServer Certificate %s",
    discovery_function=discover_xenserver_cert,
    check_function=check_xenserver_cert,
    check_default_parameters={"levels": ("fixed", (30 * 86400.0, 14 * 86400.0))},
    check_ruleset_name="xenserver_certificate",
)


# ---------------------------------------------------------------------------
# Updates
# ---------------------------------------------------------------------------
def discover_xenserver_updates(section) -> DiscoveryResult:
    if section and (section.get("latest_synced_updates_applied") is not None
                    or section.get("update_sync_enabled") is not None):
        yield Service()


def check_xenserver_updates(params, section) -> CheckResult:
    if not section:
        return
    applied = section.get("latest_synced_updates_applied")
    if applied == "no":
        yield Result(state=State(params["state_not_applied"]),
                     summary="Latest synchronized updates are not applied")
    elif applied == "yes":
        yield Result(state=State.OK, summary="Latest synchronized updates are applied")
    else:
        yield Result(state=State.OK, summary="Update state: %s" % applied)
    guidances = section.get("pending_guidances") or []
    if guidances:
        yield Result(state=State(params["state_guidance"]),
                     summary="Pending: %s" % ", ".join(guidances))
    if section.get("updates_requiring_reboot"):
        yield Result(state=State(params["state_guidance"]),
                     summary="%d update(s) require a reboot" % section["updates_requiring_reboot"])
    if section.get("last_software_update"):
        yield Result(state=State.OK, summary="Last update applied: %s" %
                     render.date(section["last_software_update"]))
    if section.get("update_sync_enabled"):
        last = section.get("last_update_sync")
        if last:
            yield from check_levels(time.time() - last, levels_upper=params.get("sync_age"),
                                    label="Last sync (%s)" % section.get("update_sync_frequency", "")
                                    if section.get("update_sync_frequency") else "Last sync",
                                    render_func=render.timespan)
        else:
            yield Result(state=State.OK, summary="Never synchronized")
    elif section.get("update_sync_enabled") is False:
        yield Result(state=State.OK, notice="Update synchronization disabled")


check_plugin_xenserver_updates = CheckPlugin(
    name="xenserver_updates",
    sections=["xenserver_host"],
    service_name="XenServer Updates",
    discovery_function=discover_xenserver_updates,
    check_function=check_xenserver_updates,
    check_default_parameters={"state_not_applied": 1, "state_guidance": 1,
                              "sync_age": ("fixed", (8 * 86400.0, 15 * 86400.0))},
    check_ruleset_name="xenserver_updates",
)
