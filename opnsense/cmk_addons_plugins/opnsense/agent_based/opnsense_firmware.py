#!/usr/bin/env python3
"""OPNsense firmware / update status check."""
import json
import time
from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Result,
    Service,
    State,
    render,
)


def parse_opnsense_firmware(string_table):
    if not string_table:
        return {}
    try:
        return json.loads(string_table[0][0])
    except (ValueError, IndexError):
        return {}


agent_section_opnsense_firmware = AgentSection(
    name="opnsense_firmware",
    parse_function=parse_opnsense_firmware,
)


def discover_opnsense_firmware(section):
    if section:
        yield Service()


def _agent_meta_results(meta, now):
    """Update-check bookkeeping of the special agent (technical timestamps)."""
    if meta.get("probe_error"):
        yield Result(state=State.WARN,
                     summary="Triggering the update check failed: %s"
                     % meta["probe_error"])
    if meta.get("probe_no_result"):
        yield Result(state=State.OK,
                     notice="Update check triggered, but OPNsense returned no "
                            "result (another firmware action may hold the "
                            "lock); retrying in %s"
                     % render.timespan(meta.get("retry_s") or 300))
    if meta.get("deferred"):
        yield Result(state=State.OK,
                     notice="Update check deferred: %s" % meta["deferred"])
    interval = meta.get("interval") or 0
    if interval <= 0:
        yield Result(state=State.OK,
                     notice="Update check not triggered by the agent "
                            "(interval 0, cached OPNsense result only)")
        return
    last_probe = meta.get("last_probe")
    if last_probe:
        yield Result(state=State.OK,
                     notice="Update check last triggered by agent: %s ago "
                            "(interval %s)"
                     % (render.timespan(max(0, now - last_probe)),
                        render.timespan(interval)))


def check_opnsense_firmware(section):
    if not section:
        return
    if "_error" in section:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % section["_error"])
        return

    meta = section.get("_agent") or {}
    product_info = section.get("product") or {}
    version = section.get("product_version") \
        or product_info.get("product_version") or "unknown"
    product = section.get("product_id") \
        or product_info.get("product_id") or "opnsense"
    status = section.get("status", "unknown")

    yield Result(state=State.OK,
                 summary="%s %s" % (product, version))

    if status == "error":
        yield Result(state=State.UNKNOWN,
                     summary="Update status unavailable: %s"
                     % (section.get("status_msg") or "error"))
    elif status == "none" and "connection" not in section \
            and "last_check" not in section:
        # OPNsense has no update check result (e.g. after a reboot); status
        # "none" with check fields just means "no updates available". The
        # agent triggers a check right away, so this should not persist.
        state = State.OK if meta.get("deferred") else State.UNKNOWN
        yield Result(state=state,
                     summary="Update status unknown: no update check result "
                             "on OPNsense yet")
    else:
        upgrade_pkgs = section.get("upgrade_packages") or []
        new_pkgs = section.get("new_packages") or []
        n_updates = len(upgrade_pkgs) + len(new_pkgs)
        needs_reboot = str(section.get("upgrade_needs_reboot", "0")) == "1" \
            or str(section.get("needs_reboot", "0")) == "1"
        if n_updates == 0 and status != "upgrade":
            yield Result(state=State.OK, summary="No updates available")
        else:
            state = State.WARN
            detail = "%d update(s) available" % n_updates
            if status == "upgrade":
                detail = "Major upgrade available"
            if needs_reboot:
                state = State.CRIT
                detail += " (reboot required)"
            yield Result(state=state, summary=detail)

    major_msg = section.get("upgrade_major_message") or ""
    if major_msg:
        yield Result(state=State.OK, notice="Upgrade note: %s" % major_msg)

    last_check = section.get("last_check")
    if last_check and last_check != "unknown":
        yield Result(state=State.OK,
                     notice="Last update check on OPNsense: %s" % last_check)

    repo = section.get("repository")
    if repo and repo != "ok":
        yield Result(state=State.WARN, summary="Repository: %s" % repo)

    if meta:
        yield from _agent_meta_results(meta, time.time())


check_plugin_opnsense_firmware = CheckPlugin(
    name="opnsense_firmware",
    service_name="OPNsense Firmware",
    discovery_function=discover_opnsense_firmware,
    check_function=check_opnsense_firmware,
)
