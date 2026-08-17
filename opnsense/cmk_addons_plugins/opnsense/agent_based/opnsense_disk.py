#!/usr/bin/env python3
"""OPNsense disk check — one Checkmk service per mounted filesystem."""
import json
from cmk.agent_based.v2 import (
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
    check_levels,
)


# Note: parsing reuses the opnsense_system section (see sections=[...] below).
def discover_opnsense_disk(section):
    disk = section.get("disk", {}) if section else {}
    if not isinstance(disk, dict) or "_error" in disk:
        return
    for dev in disk.get("devices", []):
        mp = dev.get("mountpoint")
        if mp:
            yield Service(item=mp)


def check_opnsense_disk(item, params, section):
    disk = section.get("disk", {})
    if not isinstance(disk, dict) or "_error" in disk:
        yield Result(state=State.UNKNOWN, summary="No disk data")
        return
    dev = None
    for d in disk.get("devices", []):
        if d.get("mountpoint") == item:
            dev = d
            break
    if dev is None:
        yield Result(state=State.UNKNOWN, summary="Filesystem not found")
        return

    try:
        pct = float(dev.get("used_pct", 0))
    except (ValueError, TypeError):
        pct = 0.0
    levels_upper = params.get("levels", ("fixed", (80.0, 90.0)))

    result, metric = check_levels(
        pct,
        levels_upper=levels_upper,
        metric_name="fs_used_percent",
        render_func=lambda v: "%.0f%%" % v,
        boundaries=(0, 100),
    )
    yield Result(state=result.state,
                 summary="%s used: %s (%s of %s) on %s [%s]"
                 % (item, result.summary, dev.get("used", "?"), dev.get("blocks", "?"),
                    dev.get("device", "?"), dev.get("type", "?")))
    yield metric


check_plugin_opnsense_disk = CheckPlugin(
    name="opnsense_disk",
    sections=["opnsense_system"],
    service_name="OPNsense Filesystem %s",
    discovery_function=discover_opnsense_disk,
    check_function=check_opnsense_disk,
    check_default_parameters={"levels": ("fixed", (80.0, 90.0))},
    check_ruleset_name="opnsense_disk",
)
