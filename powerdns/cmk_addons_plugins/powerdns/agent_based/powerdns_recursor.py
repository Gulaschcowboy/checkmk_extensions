#!/usr/bin/env python3
"""Check plugins for the PowerDNS Recursor.

The recursor has no zones, so the interesting signals are throughput, cache
efficiency, answer latency distribution and DNSSEC validation outcomes.  Five
services keep those groups apart so that a cache problem does not hide behind a
latency problem in the same service output.
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

SECURITY_STATUS = {
    0: "no security status known yet",
    1: "no known problems",
    2: "upgrade recommended",
    3: "upgrade mandatory, security issue",
}


def parse_powerdns_recursor(string_table: StringTable) -> Section | None:
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


def host_label_powerdns_recursor(section: Section) -> HostLabelGenerator:
    """Host label for targeting rules at recursors.

    Labels:
        powerdns/recursor:
            "yes" on hosts running the PowerDNS Recursor.
    """
    yield HostLabel("powerdns/recursor", "yes")


agent_section_powerdns_recursor = AgentSection(
    name="powerdns_recursor",
    parse_function=parse_powerdns_recursor,
    host_label_function=host_label_powerdns_recursor,
)


def _stats(section: Section) -> Mapping[str, float]:
    stats = section.get("stats")
    return stats if isinstance(stats, dict) else {}


def _rate(key: str, value: float | None, now: float) -> float | None:
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


def _per_second(value: float) -> str:
    return "%.1f/s" % value


def _count(value: float) -> str:
    return "%d" % value


# --------------------------------------------------------------------------
# PowerDNS Recursor -- overall status
# --------------------------------------------------------------------------
def discover_powerdns_recursor(section: Section) -> DiscoveryResult:
    yield Service()


def check_powerdns_recursor(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    yield Result(state=State.OK, summary="Version %s" % (section.get("version") or "unknown"))
    if section.get("source") == "control":
        yield Result(
            state=State.OK,
            notice="Data collected via rec_control, HTTP API unavailable",
        )

    stats = _stats(section)

    uptime = stats.get("uptime")
    if uptime is not None:
        yield from check_levels(
            uptime,
            levels_lower=params.get("uptime_min"),
            metric_name="pdns_recursor_uptime",
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

    concurrent = stats.get("concurrent-queries")
    max_mthreads = stats.get("max-mthreads")
    if concurrent is not None:
        yield from check_levels(
            concurrent,
            levels_upper=params.get("concurrent_queries"),
            metric_name="pdns_recursor_concurrent_queries",
            render_func=_count,
            label="Concurrent queries",
        )
        if max_mthreads:
            yield from check_levels(
                100.0 * concurrent / max_mthreads,
                levels_upper=params.get("mthread_usage"),
                metric_name="pdns_recursor_mthread_usage",
                render_func=render.percent,
                label="mthread usage",
                notice_only=True,
            )

    for key, metric, label, param in (
        ("tcp-clients", "pdns_recursor_tcp_clients", "TCP clients", "tcp_clients"),
        ("fd-usage", "pdns_recursor_fd_usage", "Open file descriptors", "fd_usage"),
    ):
        value = stats.get(key)
        if value is not None:
            yield from check_levels(
                value,
                levels_upper=params.get(param),
                metric_name=metric,
                render_func=_count,
                label=label,
                notice_only=True,
            )

    memory = stats.get("real-memory-usage")
    if memory is not None:
        yield from check_levels(
            memory,
            levels_upper=params.get("memory"),
            metric_name="pdns_recursor_memory",
            render_func=render.bytes,
            label="Memory",
            notice_only=True,
        )

    fetch = section.get("fetch_seconds")
    if fetch is not None:
        yield Metric("pdns_recursor_fetch_time", float(fetch))


check_plugin_powerdns_recursor = CheckPlugin(
    name="powerdns_recursor",
    service_name="PowerDNS Recursor",
    discovery_function=discover_powerdns_recursor,
    check_function=check_powerdns_recursor,
    check_default_parameters={
        "state_no_status": 0,
        "state_upgrade_recommended": 1,
        "state_upgrade_mandatory": 2,
        "mthread_usage": ("fixed", (70.0, 90.0)),
    },
    check_ruleset_name="powerdns_recursor",
)


# --------------------------------------------------------------------------
# PowerDNS Recursor Queries
# --------------------------------------------------------------------------
QUERY_COUNTERS = (
    ("questions", "pdns_recursor_questions", "Questions", True, None),
    ("tcp-questions", "pdns_recursor_tcp_questions", "TCP questions", False, None),
    ("all-outqueries", "pdns_recursor_outqueries", "Outgoing queries", True, None),
    ("tcp-outqueries", "pdns_recursor_tcp_outqueries", "Outgoing TCP queries", False, None),
    ("noerror-answers", "pdns_recursor_noerror_answers", "NOERROR answers", False, None),
    ("nxdomain-answers", "pdns_recursor_nxdomain_answers", "NXDOMAIN answers", False, None),
    ("servfail-answers", "pdns_recursor_servfail_answers", "SERVFAIL answers", False, "servfail"),
    ("outgoing-timeouts", "pdns_recursor_timeouts", "Outgoing timeouts", False, "timeouts"),
    ("throttled-out", "pdns_recursor_throttled_out", "Throttled outqueries", False, "throttled"),
    ("unreachables", "pdns_recursor_unreachables", "Unreachable nameservers", False, "unreachables"),
    ("over-capacity-drops", "pdns_recursor_capacity_drops", "Over capacity drops", False, "drops"),
    ("policy-drops", "pdns_recursor_policy_drops", "Policy drops", False, None),
    ("resource-limits", "pdns_recursor_resource_limits", "Resource limits hit", False, "drops"),
    ("spoof-prevents", "pdns_recursor_spoof_prevents", "Spoof attempts blocked", False, None),
    ("unauthorized-udp", "pdns_recursor_unauthorized_udp", "Unauthorized UDP", False, None),
    ("unauthorized-tcp", "pdns_recursor_unauthorized_tcp", "Unauthorized TCP", False, None),
)


def discover_powerdns_recursor_queries(section: Section) -> DiscoveryResult:
    if "questions" in _stats(section):
        yield Service()


def check_powerdns_recursor_queries(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    # Rate-only service: on the first check there is no reference value yet.
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
    for key, metric, label, in_summary, param in QUERY_COUNTERS:
        rate = _rate("rec.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        rates[key] = rate
        yield from check_levels(
            rate,
            levels_upper=params.get(param) if param else None,
            metric_name=metric,
            render_func=_per_second,
            label=label,
            notice_only=not in_summary,
        )

    questions = rates.get("questions")
    servfail = rates.get("servfail-answers")
    if servfail is not None and questions:
        yield from check_levels(
            100.0 * servfail / questions,
            levels_upper=params.get("servfail_perc"),
            metric_name="pdns_recursor_servfail_perc",
            render_func=render.percent,
            label="SERVFAIL ratio",
        )


check_plugin_powerdns_recursor_queries = CheckPlugin(
    name="powerdns_recursor_queries",
    service_name="PowerDNS Recursor Queries",
    sections=["powerdns_recursor"],
    discovery_function=discover_powerdns_recursor_queries,
    check_function=check_powerdns_recursor_queries,
    check_default_parameters={
        "servfail_perc": ("fixed", (5.0, 20.0)),
        "drops": ("fixed", (0.5, 5.0)),
    },
    check_ruleset_name="powerdns_recursor_queries",
)


# --------------------------------------------------------------------------
# PowerDNS Recursor Cache
# --------------------------------------------------------------------------
def discover_powerdns_recursor_cache(section: Section) -> DiscoveryResult:
    if "cache-entries" in _stats(section):
        yield Service()


def check_powerdns_recursor_cache(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    stats = _stats(section)
    now = time.time()

    for prefix, hit_key, miss_key, metric, label, param in (
        (
            "cache",
            "cache-hits",
            "cache-misses",
            "pdns_recursor_cache_hit_ratio",
            "Record cache hit ratio",
            "cache_hit_ratio",
        ),
        (
            "packetcache",
            "packetcache-hits",
            "packetcache-misses",
            "pdns_recursor_packetcache_hit_ratio",
            "Packet cache hit ratio",
            "packetcache_hit_ratio",
        ),
    ):
        ratio = _ratio(
            _rate("rec.%s.hit" % prefix, stats.get(hit_key), now),
            _rate("rec.%s.miss" % prefix, stats.get(miss_key), now),
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

    entries = stats.get("cache-entries")
    maximum = stats.get("max-cache-entries")
    if entries is not None:
        yield from check_levels(
            entries,
            metric_name="pdns_recursor_cache_entries",
            render_func=_count,
            label="Record cache entries",
        )
        if maximum:
            yield from check_levels(
                100.0 * entries / maximum,
                levels_upper=params.get("cache_usage"),
                metric_name="pdns_recursor_cache_usage",
                render_func=render.percent,
                label="Record cache fill",
                notice_only=True,
            )

    for key, metric, label, param in (
        (
            "packetcache-entries",
            "pdns_recursor_packetcache_entries",
            "Packet cache entries",
            None,
        ),
        ("negcache-entries", "pdns_recursor_negcache_entries", "Negative cache entries", None),
        (
            "throttle-entries",
            "pdns_recursor_throttle_entries",
            "Throttled nameservers",
            "throttle_entries",
        ),
        ("nsspeeds-entries", "pdns_recursor_nsspeeds_entries", "Nameserver speed entries", None),
        (
            "failed-host-entries",
            "pdns_recursor_failed_hosts",
            "Failed nameservers",
            "failed_hosts",
        ),
    ):
        value = stats.get(key)
        if value is not None:
            yield from check_levels(
                value,
                levels_upper=params.get(param) if param else None,
                metric_name=metric,
                render_func=_count,
                label=label,
                notice_only=True,
            )


check_plugin_powerdns_recursor_cache = CheckPlugin(
    name="powerdns_recursor_cache",
    service_name="PowerDNS Recursor Cache",
    sections=["powerdns_recursor"],
    discovery_function=discover_powerdns_recursor_cache,
    check_function=check_powerdns_recursor_cache,
    check_default_parameters={
        "cache_hit_ratio": ("no_levels", None),
        "packetcache_hit_ratio": ("no_levels", None),
        "cache_usage": ("fixed", (90.0, 98.0)),
    },
    check_ruleset_name="powerdns_recursor_cache",
)


# --------------------------------------------------------------------------
# PowerDNS Recursor Latency
# --------------------------------------------------------------------------
ANSWER_BUCKETS = (
    ("answers0-1", "pdns_recursor_answers_0_1", "0-1 ms"),
    ("answers1-10", "pdns_recursor_answers_1_10", "1-10 ms"),
    ("answers10-100", "pdns_recursor_answers_10_100", "10-100 ms"),
    ("answers100-1000", "pdns_recursor_answers_100_1000", "100-1000 ms"),
    ("answers-slow", "pdns_recursor_answers_slow", "slower than 1 s"),
)


def discover_powerdns_recursor_latency(section: Section) -> DiscoveryResult:
    if "qa-latency" in _stats(section):
        yield Service()


def check_powerdns_recursor_latency(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    stats = _stats(section)
    now = time.time()

    for key, metric, label in (
        ("qa-latency", "pdns_recursor_latency", "Question-answer latency"),
        ("x-our-latency", "pdns_recursor_our_latency", "Latency spent in the recursor"),
    ):
        value = stats.get(key)
        if value is None:
            continue
        # Both counters are reported in microseconds.
        yield from check_levels(
            float(value) / 1_000_000.0,
            levels_upper=params.get("latency") if key == "qa-latency" else None,
            metric_name=metric,
            render_func=render.timespan,
            label=label,
            notice_only=key != "qa-latency",
        )

    rates = {}
    for key, metric, label in ANSWER_BUCKETS:
        rate = _rate("rec.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        rates[key] = rate
        yield Metric(metric, rate)

    total = sum(rates.values())
    if total > 0:
        slow = rates.get("answers-slow", 0.0) + rates.get("answers100-1000", 0.0)
        yield from check_levels(
            100.0 * slow / total,
            levels_upper=params.get("slow_perc"),
            metric_name="pdns_recursor_slow_perc",
            render_func=render.percent,
            label="Answers slower than 100 ms",
        )


check_plugin_powerdns_recursor_latency = CheckPlugin(
    name="powerdns_recursor_latency",
    service_name="PowerDNS Recursor Latency",
    sections=["powerdns_recursor"],
    discovery_function=discover_powerdns_recursor_latency,
    check_function=check_powerdns_recursor_latency,
    check_default_parameters={
        "latency": ("fixed", (0.1, 0.5)),
        "slow_perc": ("fixed", (10.0, 25.0)),
    },
    check_ruleset_name="powerdns_recursor_latency",
)


# --------------------------------------------------------------------------
# PowerDNS Recursor DNSSEC
# --------------------------------------------------------------------------
DNSSEC_RESULTS = (
    ("dnssec-result-secure", "pdns_recursor_dnssec_secure", "Secure"),
    ("dnssec-result-insecure", "pdns_recursor_dnssec_insecure", "Insecure"),
    ("dnssec-result-bogus", "pdns_recursor_dnssec_bogus", "Bogus"),
    ("dnssec-result-indeterminate", "pdns_recursor_dnssec_indeterminate", "Indeterminate"),
    ("dnssec-result-nta", "pdns_recursor_dnssec_nta", "Negative trust anchor"),
)


def discover_powerdns_recursor_dnssec(section: Section) -> DiscoveryResult:
    if "dnssec-validations" in _stats(section):
        yield Service()


def check_powerdns_recursor_dnssec(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section.get("reachable"):
        yield from _unreachable(section)
        return

    # Rate-only service: on the first check there is no reference value yet.
    results = list(_dnssec_results(params, section))
    if not results:
        yield Result(state=State.OK, summary="Initializing counters")
        return
    yield from results


def _dnssec_results(params: Mapping[str, Any], section: Section) -> CheckResult:
    stats = _stats(section)
    now = time.time()

    validations = _rate("rec.dnssec-validations", stats.get("dnssec-validations"), now)
    if validations is not None:
        yield from check_levels(
            validations,
            metric_name="pdns_recursor_dnssec_validations",
            render_func=_per_second,
            label="Validations",
        )

    rates = {}
    for key, metric, label in DNSSEC_RESULTS:
        rate = _rate("rec.%s" % key, stats.get(key), now)
        if rate is None:
            continue
        rates[key] = rate
        yield from check_levels(
            rate,
            metric_name=metric,
            render_func=_per_second,
            label=label,
            notice_only=True,
        )

    total = sum(rates.values())
    bogus = rates.get("dnssec-result-bogus")
    if bogus is not None and total > 0:
        yield from check_levels(
            100.0 * bogus / total,
            levels_upper=params.get("bogus_perc"),
            metric_name="pdns_recursor_dnssec_bogus_perc",
            render_func=render.percent,
            label="Bogus ratio",
        )


check_plugin_powerdns_recursor_dnssec = CheckPlugin(
    name="powerdns_recursor_dnssec",
    service_name="PowerDNS Recursor DNSSEC",
    sections=["powerdns_recursor"],
    discovery_function=discover_powerdns_recursor_dnssec,
    check_function=check_powerdns_recursor_dnssec,
    check_default_parameters={"bogus_perc": ("fixed", (1.0, 5.0))},
    check_ruleset_name="powerdns_recursor_dnssec",
)
