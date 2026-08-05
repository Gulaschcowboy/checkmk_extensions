#!/usr/bin/env python3
"""Check plugins for the PowerDNS Authoritative Server.

Section ``powerdns_auth`` carries a single JSON object produced by the
``powerdns`` agent plugin::

    {"reachable": true, "source": "api", "version": "5.1.3",
     "stats": {"udp-queries": 1234, ...}, "errors": []}

The statistics dictionary is passed through untouched, so new counters in future
PowerDNS releases do not require a plugin change -- every check reads the keys it
knows about with ``.get()`` and silently skips the rest.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    GetRateError,
    HostLabel,
    HostLabelGenerator,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    get_rate,
    get_value_store,
    render,
)

Section = Mapping[str, Any]

# security-status as reported by the PowerDNS security polling
SECURITY_STATUS = {
    0: "no security status known yet",
    1: "no known problems",
    2: "upgrade recommended",
    3: "upgrade mandatory, security issue",
}


def parse_powerdns_auth(string_table: StringTable) -> Section | None:
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


def host_label_powerdns_auth(section: Section) -> HostLabelGenerator:
    """Host label for targeting rules at authoritative servers.

    Labels:
        powerdns/auth:
            "yes" on hosts running the PowerDNS Authoritative Server.
    """
    yield HostLabel("powerdns/auth", "yes")


agent_section_powerdns_auth = AgentSection(
    name="powerdns_auth",
    parse_function=parse_powerdns_auth,
    host_label_function=host_label_powerdns_auth,
)


# --------------------------------------------------------------------------
# helpers shared by the checks in this module
# --------------------------------------------------------------------------
def _stats(section: Section) -> Mapping[str, float]:
    stats = section.get("stats")
    return stats if isinstance(stats, dict) else {}


def _rate(key: str, value: float | None, now: float) -> float | None:
    """Counter rate, or None while no usable reference value exists.

    ``raise_overflow`` turns a counter reset (daemon restart) into a skipped
    cycle rather than a nonsensical negative rate.
    """
    if value is None:
        return None
    try:
        return get_rate(get_value_store(), key, now, float(value), raise_overflow=True)
    except GetRateError:
        return None


def _unreachable(section: Section) -> CheckResult:
    errors = section.get("errors") or ["no data"]
    yield Result(
        state=State.CRIT,
        summary="Not reachable: %s" % "; ".join(str(error) for error in errors),
    )


def _ratio(hits: float | None, misses: float | None) -> float | None:
    if hits is None or misses is None:
        return None
    total = hits + misses
    if total <= 0:
        return None
    return 100.0 * hits / total


# --------------------------------------------------------------------------
# PowerDNS Auth -- overall status
# --------------------------------------------------------------------------
def discover_powerdns_auth(section: Section) -> DiscoveryResult:
    yield Service()


def check_powerdns_auth(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    version = section.get("version")
    yield Result(state=State.OK, summary="Version %s" % (version or "unknown"))
    if section.get("source") == "control":
        yield Result(
            state=State.OK,
            notice="Data collected via control socket, HTTP API unavailable",
        )

    stats = _stats(section)

    uptime = stats.get("uptime")
    if uptime is not None:
        yield from check_levels(
            uptime,
            levels_lower=params.get("uptime_min"),
            metric_name="pdns_auth_uptime",
            render_func=render.timespan,
            label="Uptime",
        )

    security = stats.get("security-status")
    if security is not None:
        code = int(security)
        state_map = {
            0: State(params.get("state_no_status", 0)),
            1: State.OK,
            2: State(params.get("state_upgrade_recommended", 1)),
            3: State(params.get("state_upgrade_mandatory", 2)),
        }
        yield Result(
            state=state_map.get(code, State.UNKNOWN),
            notice="Security status: %s" % SECURITY_STATUS.get(code, "unknown (%d)" % code),
        )

    queue = stats.get("qsize-q")
    if queue is not None:
        yield from check_levels(
            queue,
            levels_upper=params.get("queue"),
            metric_name="pdns_auth_queue",
            render_func=lambda value: "%d" % value,
            label="Backend queue",
            notice_only=True,
        )

    memory = stats.get("real-memory-usage")
    if memory is not None:
        yield from check_levels(
            memory,
            levels_upper=params.get("memory"),
            metric_name="pdns_auth_memory",
            render_func=render.bytes,
            label="Memory",
            notice_only=True,
        )

    for key, metric, label in (
        ("fd-usage", "pdns_auth_fd_usage", "Open file descriptors"),
        ("open-tcp-connections", "pdns_auth_tcp_connections", "Open TCP connections"),
    ):
        value = stats.get(key)
        if value is not None:
            yield from check_levels(
                value,
                levels_upper=params.get(key.replace("-", "_")),
                metric_name=metric,
                render_func=lambda value: "%d" % value,
                label=label,
                notice_only=True,
            )

    fetch = section.get("fetch_seconds")
    if fetch is not None:
        yield Metric("pdns_auth_fetch_time", float(fetch))


check_plugin_powerdns_auth = CheckPlugin(
    name="powerdns_auth",
    service_name="PowerDNS Auth",
    discovery_function=discover_powerdns_auth,
    check_function=check_powerdns_auth,
    check_default_parameters={
        "state_no_status": 0,
        "state_upgrade_recommended": 1,
        "state_upgrade_mandatory": 2,
        "queue": ("fixed", (100.0, 1000.0)),
    },
    check_ruleset_name="powerdns_auth",
)


# --------------------------------------------------------------------------
# PowerDNS Auth Queries
# --------------------------------------------------------------------------
QUERY_COUNTERS = (
    # stat key, metric, label, show in summary
    ("udp-queries", "pdns_auth_udp_queries", "UDP queries", True),
    ("tcp-queries", "pdns_auth_tcp_queries", "TCP queries", True),
    ("udp-answers", "pdns_auth_udp_answers", "UDP answers", False),
    ("tcp-answers", "pdns_auth_tcp_answers", "TCP answers", False),
    ("rd-queries", "pdns_auth_rd_queries", "Recursion desired", False),
    ("dnsupdate-queries", "pdns_auth_dnsupdate_queries", "DNS UPDATE queries", False),
    ("signatures", "pdns_auth_signatures", "DNSSEC signatures", False),
)

ERROR_COUNTERS = (
    ("servfail-packets", "pdns_auth_servfail", "SERVFAIL", "servfail"),
    ("corrupt-packets", "pdns_auth_corrupt", "Corrupt packets", "corrupt"),
    ("timedout-packets", "pdns_auth_timedout", "Timed out", "timedout"),
    ("overload-drops", "pdns_auth_overload_drops", "Overload drops", "overload_drops"),
)


def discover_powerdns_auth_queries(section: Section) -> DiscoveryResult:
    if "udp-queries" in _stats(section):
        yield Service()


def check_powerdns_auth_queries(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    # Every value here is a counter rate, so the very first check after
    # discovery has no reference value and would otherwise render an empty
    # service.
    results = list(_query_results(params, section))
    if not results:
        yield Result(state=State.OK, summary="Initializing counters")
        return
    yield from results


def _query_results(params: Mapping[str, Any], section: Section) -> CheckResult:
    stats = _stats(section)
    now = time.time()

    # Each counter rate must be computed exactly once per check: get_rate stores
    # the new reference value, so a second call in the same run sees no elapsed
    # time and yields nothing.
    rates: dict[str, float] = {}
    for key, metric, label, in_summary in QUERY_COUNTERS:
        rate = _rate("auth.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        rates[key] = rate
        yield from check_levels(
            rate,
            levels_upper=params.get(key.replace("-", "_")),
            metric_name=metric,
            render_func=lambda value: "%.1f/s" % value,
            label=label,
            notice_only=not in_summary,
        )

    queries = sum(
        rates[key] for key in ("udp-queries", "tcp-queries") if key in rates
    ) or None
    for key, metric, label, param in ERROR_COUNTERS:
        rate = _rate("auth.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        yield from check_levels(
            rate,
            levels_upper=params.get(param),
            metric_name=metric,
            render_func=lambda value: "%.2f/s" % value,
            label=label,
            notice_only=True,
        )
        if param == "servfail" and queries:
            yield from check_levels(
                100.0 * rate / queries,
                levels_upper=params.get("servfail_perc"),
                metric_name="pdns_auth_servfail_perc",
                render_func=render.percent,
                label="SERVFAIL ratio",
                notice_only=True,
            )


check_plugin_powerdns_auth_queries = CheckPlugin(
    name="powerdns_auth_queries",
    service_name="PowerDNS Auth Queries",
    sections=["powerdns_auth"],
    discovery_function=discover_powerdns_auth_queries,
    check_function=check_powerdns_auth_queries,
    check_default_parameters={
        "servfail_perc": ("fixed", (5.0, 20.0)),
        "corrupt": ("fixed", (1.0, 10.0)),
        "overload_drops": ("fixed", (0.5, 5.0)),
    },
    check_ruleset_name="powerdns_auth_queries",
)


# --------------------------------------------------------------------------
# PowerDNS Auth Cache
# --------------------------------------------------------------------------
def discover_powerdns_auth_cache(section: Section) -> DiscoveryResult:
    if "packetcache-hit" in _stats(section) or "query-cache-hit" in _stats(section):
        yield Service()


def check_powerdns_auth_cache(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    stats = _stats(section)
    now = time.time()

    for prefix, hit_key, miss_key, metric, label, param in (
        (
            "packetcache",
            "packetcache-hit",
            "packetcache-miss",
            "pdns_auth_packetcache_hit_ratio",
            "Packet cache hit ratio",
            "packetcache_hit_ratio",
        ),
        (
            "querycache",
            "query-cache-hit",
            "query-cache-miss",
            "pdns_auth_querycache_hit_ratio",
            "Query cache hit ratio",
            "querycache_hit_ratio",
        ),
    ):
        ratio = _ratio(
            _rate("auth.%s.hit" % prefix, stats.get(hit_key), now),
            _rate("auth.%s.miss" % prefix, stats.get(miss_key), now),
        )
        if ratio is None:
            continue
        yield from check_levels(
            ratio,
            levels_lower=params.get(param),
            metric_name=metric,
            render_func=render.percent,
            label=label,
        )

    for key, metric, label in (
        ("packetcache-size", "pdns_auth_packetcache_size", "Packet cache entries"),
        ("query-cache-size", "pdns_auth_querycache_size", "Query cache entries"),
        ("key-cache-size", "pdns_auth_key_cache_size", "Key cache entries"),
        ("meta-cache-size", "pdns_auth_meta_cache_size", "Metadata cache entries"),
        ("signature-cache-size", "pdns_auth_signature_cache_size", "Signature cache entries"),
    ):
        value = stats.get(key)
        if value is not None:
            yield from check_levels(
                value,
                metric_name=metric,
                render_func=lambda value: "%d" % value,
                label=label,
                notice_only=True,
            )

    for key, metric, label, param in (
        (
            "deferred-cache-inserts",
            "pdns_auth_deferred_inserts",
            "Deferred cache inserts",
            "deferred_inserts",
        ),
        (
            "deferred-cache-lookup",
            "pdns_auth_deferred_lookups",
            "Deferred cache lookups",
            "deferred_lookups",
        ),
    ):
        rate = _rate("auth.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        yield from check_levels(
            rate,
            levels_upper=params.get(param),
            metric_name=metric,
            render_func=lambda value: "%.2f/s" % value,
            label=label,
            notice_only=True,
        )


check_plugin_powerdns_auth_cache = CheckPlugin(
    name="powerdns_auth_cache",
    service_name="PowerDNS Auth Cache",
    sections=["powerdns_auth"],
    discovery_function=discover_powerdns_auth_cache,
    check_function=check_powerdns_auth_cache,
    check_default_parameters={
        "packetcache_hit_ratio": ("no_levels", None),
        "querycache_hit_ratio": ("no_levels", None),
        "deferred_inserts": ("fixed", (1.0, 10.0)),
        "deferred_lookups": ("fixed", (1.0, 10.0)),
    },
    check_ruleset_name="powerdns_auth_cache",
)


# --------------------------------------------------------------------------
# PowerDNS Auth Latency
# --------------------------------------------------------------------------
def discover_powerdns_auth_latency(section: Section) -> DiscoveryResult:
    if "latency" in _stats(section):
        yield Service()


def check_powerdns_auth_latency(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    latency = _stats(section).get("latency")
    if latency is None:
        return
    # PowerDNS reports the average answer latency in microseconds.
    yield from check_levels(
        float(latency) / 1_000_000.0,
        levels_upper=params.get("latency"),
        metric_name="pdns_auth_latency",
        render_func=render.timespan,
        label="Average answer latency",
    )


check_plugin_powerdns_auth_latency = CheckPlugin(
    name="powerdns_auth_latency",
    service_name="PowerDNS Auth Latency",
    sections=["powerdns_auth"],
    discovery_function=discover_powerdns_auth_latency,
    check_function=check_powerdns_auth_latency,
    check_default_parameters={"latency": ("fixed", (0.05, 0.2))},
    check_ruleset_name="powerdns_auth_latency",
)
