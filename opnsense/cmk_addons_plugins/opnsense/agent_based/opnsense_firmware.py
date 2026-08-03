#!/usr/bin/env python3
"""OPNsense firmware / update status check."""
import json
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


def check_opnsense_firmware(section):
    if not section:
        return
    if "_error" in section:
        yield Result(state=State.UNKNOWN,
                     summary="API error: %s" % section["_error"])
        return

    version = section.get("product_version", "unknown")
    product = section.get("product_id", "opnsense")
    status = section.get("status", "unknown")

    upgrade_pkgs = section.get("upgrade_packages") or []
    new_pkgs = section.get("new_packages") or []
    n_updates = len(upgrade_pkgs) + len(new_pkgs)

    needs_reboot = str(section.get("upgrade_needs_reboot", "0")) == "1" \
        or str(section.get("needs_reboot", "0")) == "1"

    yield Result(state=State.OK,
                 summary="%s %s" % (product, version))

    if status == "none" or (n_updates == 0 and status != "upgrade"):
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
    if last_check:
        yield Result(state=State.OK, notice="Last check: %s" % last_check)

    repo = section.get("repository")
    if repo and repo != "ok":
        yield Result(state=State.WARN, summary="Repository: %s" % repo)


check_plugin_opnsense_firmware = CheckPlugin(
    name="opnsense_firmware",
    service_name="OPNsense Firmware",
    discovery_function=discover_opnsense_firmware,
    check_function=check_opnsense_firmware,
)
