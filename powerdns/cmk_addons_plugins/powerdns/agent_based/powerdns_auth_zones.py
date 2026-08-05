#!/usr/bin/env python3
"""Zone monitoring for the PowerDNS Authoritative Server.

Two check plugins consume the ``powerdns_auth_zones`` section:

``powerdns_zones``
    One summary service: how many zones exist, split by kind, how many are
    DNSSEC signed, and the total number of records.  Always discovered.

``powerdns_zone``
    One service per zone, item = zone name without the trailing dot.  Carries
    the per-zone record count as a metric (this is the graph you want) plus the
    operational checks that make the count trustworthy: serial vs.
    notified_serial for primaries, last_check age for secondaries, and a
    relative-drop check that catches accidental mass deletion.

Which zones become services is controlled by the ``discovery_powerdns_zones``
ruleset -- on a server with thousands of zones you do not want thousands of
services, so filtering is a first-class feature rather than an afterthought.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    RuleSetType,
    Service,
    ServiceLabel,
    State,
    StringTable,
    check_levels,
    get_value_store,
    render,
)

Section = Mapping[str, Any]

PRIMARY_KINDS = ("Master", "Producer")
SECONDARY_KINDS = ("Slave", "Consumer")


def parse_powerdns_auth_zones(string_table: StringTable) -> Section | None:
    raw = "".join(line[0] for line in string_table if line)
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


agent_section_powerdns_auth_zones = AgentSection(
    name="powerdns_auth_zones",
    parse_function=parse_powerdns_auth_zones,
)


def _zones(section: Section) -> Sequence[Mapping[str, Any]]:
    zones = section.get("zones")
    return [zone for zone in zones if isinstance(zone, dict)] if isinstance(zones, list) else []


def _display_name(zone: Mapping[str, Any]) -> str:
    """Zone name without the trailing dot -- that is what operators type."""
    name = str(zone.get("name") or zone.get("id") or "")
    return name[:-1] if name.endswith(".") else name


def _matches(name: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, name):
                return True
        except re.error:
            continue
    return False


# --------------------------------------------------------------------------
# PowerDNS Zones -- summary
# --------------------------------------------------------------------------
def discover_powerdns_zones(section: Section) -> DiscoveryResult:
    yield Service()


def check_powerdns_zones(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        errors = section.get("errors") or ["no data"]
        yield Result(
            state=State.CRIT,
            summary="Zone inventory unavailable: %s"
            % "; ".join(str(error) for error in errors),
        )
        return

    zones = _zones(section)

    yield from check_levels(
        len(zones),
        levels_upper=params.get("zone_count_upper"),
        levels_lower=params.get("zone_count_lower"),
        metric_name="pdns_zones",
        render_func=lambda value: "%d" % value,
        label="Zones",
    )

    by_kind: dict[str, int] = {}
    for zone in zones:
        kind = str(zone.get("kind") or "Unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
    if by_kind:
        yield Result(
            state=State.OK,
            notice="By kind: %s"
            % ", ".join("%s %d" % (kind, count) for kind, count in sorted(by_kind.items())),
        )
    for kind, metric in (
        ("Native", "pdns_zones_native"),
        ("Master", "pdns_zones_primary"),
        ("Slave", "pdns_zones_secondary"),
        ("Producer", "pdns_zones_producer"),
        ("Consumer", "pdns_zones_consumer"),
    ):
        yield Metric(metric, by_kind.get(kind, 0))

    signed = sum(1 for zone in zones if zone.get("dnssec"))
    yield from check_levels(
        signed,
        metric_name="pdns_zones_dnssec",
        render_func=lambda value: "%d" % value,
        label="DNSSEC signed",
        notice_only=True,
    )

    counted = [zone["records"] for zone in zones if isinstance(zone.get("records"), (int, float))]
    if counted:
        yield from check_levels(
            sum(counted),
            levels_upper=params.get("record_count_upper"),
            levels_lower=params.get("record_count_lower"),
            metric_name="pdns_records_total",
            render_func=lambda value: "%d" % value,
            label="Records total",
        )
    if len(counted) < len(zones):
        yield Result(
            state=State.OK,
            notice="Record counts available for %d of %d zones" % (len(counted), len(zones)),
        )

    empty = [_display_name(zone) for zone in zones if zone.get("records") == 0]
    if empty:
        yield Result(
            state=State(params.get("state_empty_zone", 1)),
            summary="%d zone(s) without records" % len(empty),
            details="Zones without records: %s" % ", ".join(sorted(empty)[:20]),
        )

    if section.get("truncated"):
        yield Result(
            state=State.WARN,
            summary="Zone list truncated (%s zones on the server, raise max_zones)"
            % section.get("total_zones", "?"),
        )

    age = section.get("records_age")
    if age is not None:
        yield from check_levels(
            float(age),
            levels_upper=params.get("records_age"),
            metric_name="pdns_records_age",
            render_func=render.timespan,
            label="Record counts age",
            notice_only=True,
        )

    for error in section.get("errors") or []:
        yield Result(state=State.WARN, notice="Collector warning: %s" % error)


check_plugin_powerdns_zones = CheckPlugin(
    name="powerdns_zones",
    service_name="PowerDNS Zones",
    sections=["powerdns_auth_zones"],
    discovery_function=discover_powerdns_zones,
    check_function=check_powerdns_zones,
    check_default_parameters={
        "state_empty_zone": 1,
        "records_age": ("fixed", (7200.0, 21600.0)),
    },
    check_ruleset_name="powerdns_zones",
)


# --------------------------------------------------------------------------
# PowerDNS Zone <name> -- one service per zone
# --------------------------------------------------------------------------
def discover_powerdns_zone(
    params: Mapping[str, Any],
    section: Section,
) -> DiscoveryResult:
    if params.get("mode", "per_zone") != "per_zone":
        return

    include = params.get("include") or []
    exclude = params.get("exclude") or []
    kinds = params.get("kinds")

    for zone in _zones(section):
        name = _display_name(zone)
        if not name:
            continue
        kind = str(zone.get("kind") or "Unknown")
        if kinds and kind not in kinds:
            continue
        if include and not _matches(name, include):
            continue
        if exclude and _matches(name, exclude):
            continue

        labels = [
            ServiceLabel("powerdns/zone_kind", kind),
            ServiceLabel("powerdns/dnssec", "yes" if zone.get("dnssec") else "no"),
        ]
        if zone.get("catalog"):
            labels.append(ServiceLabel("powerdns/catalog", str(zone["catalog"])))
        yield Service(item=name, labels=labels)


def check_powerdns_zone(
    item: str,
    params: Mapping[str, Any],
    section: Section,
) -> CheckResult:
    zone = next((zone for zone in _zones(section) if _display_name(zone) == item), None)
    if zone is None:
        if not section.get("reachable"):
            yield Result(state=State.CRIT, summary="Zone inventory unavailable")
        return

    kind = str(zone.get("kind") or "Unknown")
    yield Result(state=State.OK, summary="Kind: %s" % kind)

    records = zone.get("records")
    if isinstance(records, (int, float)):
        yield from check_levels(
            int(records),
            levels_upper=params.get("records_upper"),
            levels_lower=params.get("records_lower"),
            metric_name="pdns_zone_records",
            render_func=lambda value: "%d" % value,
            label="Records",
        )
        yield from _check_record_drop(int(records), params)
    else:
        yield Result(state=State.OK, notice="Record count not collected")

    rrsets = zone.get("rrsets")
    if isinstance(rrsets, (int, float)):
        yield from check_levels(
            int(rrsets),
            metric_name="pdns_zone_rrsets",
            render_func=lambda value: "%d" % value,
            label="RRsets",
            notice_only=True,
        )

    serial = zone.get("serial")
    if serial is not None:
        yield Result(state=State.OK, notice="Serial: %s" % serial)
    if zone.get("edited_serial") not in (None, serial):
        yield Result(state=State.OK, notice="Serial in answers: %s" % zone["edited_serial"])

    yield Result(
        state=State(params.get("state_unsigned", 0)) if not zone.get("dnssec") else State.OK,
        notice="DNSSEC: %s" % ("signed" if zone.get("dnssec") else "unsigned"),
    )

    if kind in PRIMARY_KINDS:
        yield from _check_notify(zone, params)
    if kind in SECONDARY_KINDS:
        yield from _check_secondary(zone, params)


def _check_record_drop(records: int, params: Mapping[str, Any]) -> CheckResult:
    """Warn when a zone loses a large share of its records between checks.

    Absolute levels cannot express "this zone shrank by half" without per-zone
    tuning, so the drop is evaluated relatively against the previous value.
    """
    levels = params.get("records_drop_perc")
    if not levels or levels[0] != "fixed":
        return
    warn, crit = levels[1]

    store = get_value_store()
    previous = store.get("records")
    store["records"] = records

    if not isinstance(previous, (int, float)) or previous <= 0 or records >= previous:
        return

    drop = 100.0 * (previous - records) / previous
    state = State.CRIT if drop >= crit else State.WARN if drop >= warn else State.OK
    if state is not State.OK:
        yield Result(
            state=state,
            summary="Record count dropped by %s (from %d)" % (render.percent(drop), previous),
        )


def _check_notify(zone: Mapping[str, Any], params: Mapping[str, Any]) -> CheckResult:
    """For primaries: has the current serial been notified to the secondaries?

    A momentary mismatch is normal right after an edit, so the mismatch has to
    persist before it is reported.  The first time we see it is remembered in the
    value store.
    """
    serial = zone.get("serial")
    notified = zone.get("notified_serial")
    if serial is None or notified is None:
        return

    store = get_value_store()
    if notified >= serial:
        store.pop("notify_since", None)
        return

    now = time.time()
    since = store.get("notify_since")
    if not isinstance(since, (int, float)):
        since = now
        store["notify_since"] = since
    age = now - since

    levels = params.get("notify_lag")
    state = State.OK
    if levels and levels[0] == "fixed":
        warn, crit = levels[1]
        state = State.CRIT if age >= crit else State.WARN if age >= warn else State.OK
    yield Result(
        state=state,
        summary="Serial %s not notified yet (notified: %s, since %s)"
        % (serial, notified, render.timespan(age)),
    )


def _check_secondary(zone: Mapping[str, Any], params: Mapping[str, Any]) -> CheckResult:
    """For secondaries: how long ago did we successfully check the primary?"""
    last_check = zone.get("last_check")
    if not isinstance(last_check, (int, float)) or last_check <= 0:
        yield Result(
            state=State(params.get("state_never_checked", 1)),
            summary="Never successfully transferred from the primary",
        )
        return

    yield from check_levels(
        max(0.0, time.time() - float(last_check)),
        levels_upper=params.get("last_check_age"),
        metric_name="pdns_zone_last_check_age",
        render_func=render.timespan,
        label="Last check",
    )


check_plugin_powerdns_zone = CheckPlugin(
    name="powerdns_zone",
    service_name="PowerDNS Zone %s",
    sections=["powerdns_auth_zones"],
    discovery_function=discover_powerdns_zone,
    discovery_default_parameters={"mode": "per_zone"},
    discovery_ruleset_name="discovery_powerdns_zones",
    discovery_ruleset_type=RuleSetType.MERGED,
    check_function=check_powerdns_zone,
    check_default_parameters={
        "records_lower": ("fixed", (1, 0)),
        "records_drop_perc": ("fixed", (25.0, 50.0)),
        "notify_lag": ("fixed", (900.0, 3600.0)),
        "last_check_age": ("fixed", (7200.0, 86400.0)),
        "state_never_checked": 1,
        "state_unsigned": 0,
    },
    check_ruleset_name="powerdns_zone",
)
