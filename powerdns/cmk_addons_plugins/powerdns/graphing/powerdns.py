#!/usr/bin/env python3
"""Metric, graph and perfometer definitions for the PowerDNS plugins.

Every metric emitted by the check plugins is defined here so that it gets a
title, a unit and a stable colour instead of the generic auto-rendering.  The
graphs group metrics the way an operator reads them: queries against answers,
hits against misses, latency buckets stacked.
"""

from cmk.graphing.v1 import Title, graphs, metrics, perfometers

UNIT_COUNT = metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(0))
UNIT_PER_SECOND = metrics.Unit(metrics.DecimalNotation("/s"))
UNIT_PERCENT = metrics.Unit(metrics.DecimalNotation("%"))
UNIT_SECONDS = metrics.Unit(metrics.TimeNotation())
UNIT_BYTES = metrics.Unit(metrics.IECNotation("B"))

# --------------------------------------------------------------------------
# Authoritative server: process
# --------------------------------------------------------------------------
metric_pdns_auth_uptime = metrics.Metric(
    name="pdns_auth_uptime",
    title=Title("Uptime"),
    unit=UNIT_SECONDS,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_auth_memory = metrics.Metric(
    name="pdns_auth_memory",
    title=Title("Memory used"),
    unit=UNIT_BYTES,
    color=metrics.Color.PURPLE,
)
metric_pdns_auth_queue = metrics.Metric(
    name="pdns_auth_queue",
    title=Title("Queued backend questions"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)
metric_pdns_auth_fd_usage = metrics.Metric(
    name="pdns_auth_fd_usage",
    title=Title("Open file descriptors"),
    unit=UNIT_COUNT,
    color=metrics.Color.CYAN,
)
metric_pdns_auth_tcp_connections = metrics.Metric(
    name="pdns_auth_tcp_connections",
    title=Title("Open TCP connections"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_auth_fetch_time = metrics.Metric(
    name="pdns_auth_fetch_time",
    title=Title("Statistics collection time"),
    unit=UNIT_SECONDS,
    color=metrics.Color.GRAY,
)

# --------------------------------------------------------------------------
# Authoritative server: queries
# --------------------------------------------------------------------------
metric_pdns_auth_udp_queries = metrics.Metric(
    name="pdns_auth_udp_queries",
    title=Title("UDP queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.BLUE,
)
metric_pdns_auth_udp_answers = metrics.Metric(
    name="pdns_auth_udp_answers",
    title=Title("UDP answers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_auth_tcp_queries = metrics.Metric(
    name="pdns_auth_tcp_queries",
    title=Title("TCP queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.GREEN,
)
metric_pdns_auth_tcp_answers = metrics.Metric(
    name="pdns_auth_tcp_answers",
    title=Title("TCP answers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.LIGHT_GREEN,
)
metric_pdns_auth_rd_queries = metrics.Metric(
    name="pdns_auth_rd_queries",
    title=Title("Queries with recursion desired"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.YELLOW,
)
metric_pdns_auth_dnsupdate_queries = metrics.Metric(
    name="pdns_auth_dnsupdate_queries",
    title=Title("DNS UPDATE queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.ORANGE,
)
metric_pdns_auth_signatures = metrics.Metric(
    name="pdns_auth_signatures",
    title=Title("DNSSEC signatures created"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.PURPLE,
)
metric_pdns_auth_servfail = metrics.Metric(
    name="pdns_auth_servfail",
    title=Title("SERVFAIL packets"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.RED,
)
metric_pdns_auth_servfail_perc = metrics.Metric(
    name="pdns_auth_servfail_perc",
    title=Title("SERVFAIL ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.DARK_RED,
)
metric_pdns_auth_corrupt = metrics.Metric(
    name="pdns_auth_corrupt",
    title=Title("Corrupt packets"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_ORANGE,
)
metric_pdns_auth_timedout = metrics.Metric(
    name="pdns_auth_timedout",
    title=Title("Timed out packets"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.ORANGE,
)
metric_pdns_auth_overload_drops = metrics.Metric(
    name="pdns_auth_overload_drops",
    title=Title("Overload drops"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_RED,
)

# --------------------------------------------------------------------------
# Authoritative server: caches
# --------------------------------------------------------------------------
metric_pdns_auth_packetcache_hit_ratio = metrics.Metric(
    name="pdns_auth_packetcache_hit_ratio",
    title=Title("Packet cache hit ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.GREEN,
)
metric_pdns_auth_querycache_hit_ratio = metrics.Metric(
    name="pdns_auth_querycache_hit_ratio",
    title=Title("Query cache hit ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.BLUE,
)
metric_pdns_auth_packetcache_size = metrics.Metric(
    name="pdns_auth_packetcache_size",
    title=Title("Packet cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)
metric_pdns_auth_querycache_size = metrics.Metric(
    name="pdns_auth_querycache_size",
    title=Title("Query cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_auth_key_cache_size = metrics.Metric(
    name="pdns_auth_key_cache_size",
    title=Title("Key cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.PURPLE,
)
metric_pdns_auth_meta_cache_size = metrics.Metric(
    name="pdns_auth_meta_cache_size",
    title=Title("Metadata cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.CYAN,
)
metric_pdns_auth_signature_cache_size = metrics.Metric(
    name="pdns_auth_signature_cache_size",
    title=Title("Signature cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)
metric_pdns_auth_deferred_inserts = metrics.Metric(
    name="pdns_auth_deferred_inserts",
    title=Title("Deferred cache inserts"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_ORANGE,
)
metric_pdns_auth_deferred_lookups = metrics.Metric(
    name="pdns_auth_deferred_lookups",
    title=Title("Deferred cache lookups"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_YELLOW,
)
metric_pdns_auth_latency = metrics.Metric(
    name="pdns_auth_latency",
    title=Title("Average answer latency"),
    unit=UNIT_SECONDS,
    color=metrics.Color.ORANGE,
)

# --------------------------------------------------------------------------
# Zones
# --------------------------------------------------------------------------
metric_pdns_zones = metrics.Metric(
    name="pdns_zones",
    title=Title("Zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_zones_native = metrics.Metric(
    name="pdns_zones_native",
    title=Title("Native zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_zones_primary = metrics.Metric(
    name="pdns_zones_primary",
    title=Title("Primary zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)
metric_pdns_zones_secondary = metrics.Metric(
    name="pdns_zones_secondary",
    title=Title("Secondary zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.YELLOW,
)
metric_pdns_zones_producer = metrics.Metric(
    name="pdns_zones_producer",
    title=Title("Producer zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)
metric_pdns_zones_consumer = metrics.Metric(
    name="pdns_zones_consumer",
    title=Title("Consumer zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.PURPLE,
)
metric_pdns_zones_dnssec = metrics.Metric(
    name="pdns_zones_dnssec",
    title=Title("DNSSEC signed zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.DARK_GREEN,
)
metric_pdns_records_total = metrics.Metric(
    name="pdns_records_total",
    title=Title("Records in all zones"),
    unit=UNIT_COUNT,
    color=metrics.Color.DARK_BLUE,
)
metric_pdns_records_age = metrics.Metric(
    name="pdns_records_age",
    title=Title("Age of the record counts"),
    unit=UNIT_SECONDS,
    color=metrics.Color.GRAY,
)
metric_pdns_zone_records = metrics.Metric(
    name="pdns_zone_records",
    title=Title("Records in zone"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_zone_rrsets = metrics.Metric(
    name="pdns_zone_rrsets",
    title=Title("RRsets in zone"),
    unit=UNIT_COUNT,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_zone_last_check_age = metrics.Metric(
    name="pdns_zone_last_check_age",
    title=Title("Time since last successful check of the primary"),
    unit=UNIT_SECONDS,
    color=metrics.Color.ORANGE,
)

# --------------------------------------------------------------------------
# Recursor: process
# --------------------------------------------------------------------------
metric_pdns_recursor_uptime = metrics.Metric(
    name="pdns_recursor_uptime",
    title=Title("Uptime"),
    unit=UNIT_SECONDS,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_recursor_memory = metrics.Metric(
    name="pdns_recursor_memory",
    title=Title("Memory used"),
    unit=UNIT_BYTES,
    color=metrics.Color.PURPLE,
)
metric_pdns_recursor_fd_usage = metrics.Metric(
    name="pdns_recursor_fd_usage",
    title=Title("Open file descriptors"),
    unit=UNIT_COUNT,
    color=metrics.Color.CYAN,
)
metric_pdns_recursor_concurrent_queries = metrics.Metric(
    name="pdns_recursor_concurrent_queries",
    title=Title("Concurrent queries"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_recursor_mthread_usage = metrics.Metric(
    name="pdns_recursor_mthread_usage",
    title=Title("mthread usage"),
    unit=UNIT_PERCENT,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_tcp_clients = metrics.Metric(
    name="pdns_recursor_tcp_clients",
    title=Title("TCP clients"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_fetch_time = metrics.Metric(
    name="pdns_recursor_fetch_time",
    title=Title("Statistics collection time"),
    unit=UNIT_SECONDS,
    color=metrics.Color.GRAY,
)

# --------------------------------------------------------------------------
# Recursor: queries
# --------------------------------------------------------------------------
metric_pdns_recursor_questions = metrics.Metric(
    name="pdns_recursor_questions",
    title=Title("Questions received"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.BLUE,
)
metric_pdns_recursor_tcp_questions = metrics.Metric(
    name="pdns_recursor_tcp_questions",
    title=Title("TCP questions received"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.LIGHT_BLUE,
)
metric_pdns_recursor_outqueries = metrics.Metric(
    name="pdns_recursor_outqueries",
    title=Title("Outgoing queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_tcp_outqueries = metrics.Metric(
    name="pdns_recursor_tcp_outqueries",
    title=Title("Outgoing TCP queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.LIGHT_GREEN,
)
metric_pdns_recursor_noerror_answers = metrics.Metric(
    name="pdns_recursor_noerror_answers",
    title=Title("NOERROR answers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_nxdomain_answers = metrics.Metric(
    name="pdns_recursor_nxdomain_answers",
    title=Title("NXDOMAIN answers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.YELLOW,
)
metric_pdns_recursor_servfail_answers = metrics.Metric(
    name="pdns_recursor_servfail_answers",
    title=Title("SERVFAIL answers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.RED,
)
metric_pdns_recursor_servfail_perc = metrics.Metric(
    name="pdns_recursor_servfail_perc",
    title=Title("SERVFAIL ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.DARK_RED,
)
metric_pdns_recursor_timeouts = metrics.Metric(
    name="pdns_recursor_timeouts",
    title=Title("Outgoing timeouts"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_throttled_out = metrics.Metric(
    name="pdns_recursor_throttled_out",
    title=Title("Throttled outgoing queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_YELLOW,
)
metric_pdns_recursor_unreachables = metrics.Metric(
    name="pdns_recursor_unreachables",
    title=Title("Unreachable nameservers"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_ORANGE,
)
metric_pdns_recursor_capacity_drops = metrics.Metric(
    name="pdns_recursor_capacity_drops",
    title=Title("Over capacity drops"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_RED,
)
metric_pdns_recursor_policy_drops = metrics.Metric(
    name="pdns_recursor_policy_drops",
    title=Title("Policy drops"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.PURPLE,
)
metric_pdns_recursor_resource_limits = metrics.Metric(
    name="pdns_recursor_resource_limits",
    title=Title("Resource limits hit"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.RED,
)
metric_pdns_recursor_spoof_prevents = metrics.Metric(
    name="pdns_recursor_spoof_prevents",
    title=Title("Spoofing attempts blocked"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_PURPLE,
)
metric_pdns_recursor_unauthorized_udp = metrics.Metric(
    name="pdns_recursor_unauthorized_udp",
    title=Title("Unauthorized UDP queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_CYAN,
)
metric_pdns_recursor_unauthorized_tcp = metrics.Metric(
    name="pdns_recursor_unauthorized_tcp",
    title=Title("Unauthorized TCP queries"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.CYAN,
)

# --------------------------------------------------------------------------
# Recursor: caches
# --------------------------------------------------------------------------
metric_pdns_recursor_cache_hit_ratio = metrics.Metric(
    name="pdns_recursor_cache_hit_ratio",
    title=Title("Record cache hit ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_packetcache_hit_ratio = metrics.Metric(
    name="pdns_recursor_packetcache_hit_ratio",
    title=Title("Packet cache hit ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.BLUE,
)
metric_pdns_recursor_cache_entries = metrics.Metric(
    name="pdns_recursor_cache_entries",
    title=Title("Record cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_cache_usage = metrics.Metric(
    name="pdns_recursor_cache_usage",
    title=Title("Record cache fill level"),
    unit=UNIT_PERCENT,
    color=metrics.Color.DARK_GREEN,
)
metric_pdns_recursor_packetcache_entries = metrics.Metric(
    name="pdns_recursor_packetcache_entries",
    title=Title("Packet cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.BLUE,
)
metric_pdns_recursor_negcache_entries = metrics.Metric(
    name="pdns_recursor_negcache_entries",
    title=Title("Negative cache entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.YELLOW,
)
metric_pdns_recursor_throttle_entries = metrics.Metric(
    name="pdns_recursor_throttle_entries",
    title=Title("Throttled nameservers"),
    unit=UNIT_COUNT,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_nsspeeds_entries = metrics.Metric(
    name="pdns_recursor_nsspeeds_entries",
    title=Title("Nameserver speed entries"),
    unit=UNIT_COUNT,
    color=metrics.Color.CYAN,
)
metric_pdns_recursor_failed_hosts = metrics.Metric(
    name="pdns_recursor_failed_hosts",
    title=Title("Failed nameservers"),
    unit=UNIT_COUNT,
    color=metrics.Color.RED,
)

# --------------------------------------------------------------------------
# Recursor: latency
# --------------------------------------------------------------------------
metric_pdns_recursor_latency = metrics.Metric(
    name="pdns_recursor_latency",
    title=Title("Question-answer latency"),
    unit=UNIT_SECONDS,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_our_latency = metrics.Metric(
    name="pdns_recursor_our_latency",
    title=Title("Latency spent inside the recursor"),
    unit=UNIT_SECONDS,
    color=metrics.Color.YELLOW,
)
metric_pdns_recursor_answers_0_1 = metrics.Metric(
    name="pdns_recursor_answers_0_1",
    title=Title("Answers within 1 ms"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_GREEN,
)
metric_pdns_recursor_answers_1_10 = metrics.Metric(
    name="pdns_recursor_answers_1_10",
    title=Title("Answers within 1-10 ms"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.GREEN,
)
metric_pdns_recursor_answers_10_100 = metrics.Metric(
    name="pdns_recursor_answers_10_100",
    title=Title("Answers within 10-100 ms"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.YELLOW,
)
metric_pdns_recursor_answers_100_1000 = metrics.Metric(
    name="pdns_recursor_answers_100_1000",
    title=Title("Answers within 100-1000 ms"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_answers_slow = metrics.Metric(
    name="pdns_recursor_answers_slow",
    title=Title("Answers slower than 1 s"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.RED,
)
metric_pdns_recursor_slow_perc = metrics.Metric(
    name="pdns_recursor_slow_perc",
    title=Title("Answers slower than 100 ms"),
    unit=UNIT_PERCENT,
    color=metrics.Color.DARK_ORANGE,
)

# --------------------------------------------------------------------------
# Recursor: DNSSEC
# --------------------------------------------------------------------------
metric_pdns_recursor_dnssec_validations = metrics.Metric(
    name="pdns_recursor_dnssec_validations",
    title=Title("DNSSEC validations"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.BLUE,
)
metric_pdns_recursor_dnssec_secure = metrics.Metric(
    name="pdns_recursor_dnssec_secure",
    title=Title("DNSSEC secure"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.DARK_GREEN,
)
metric_pdns_recursor_dnssec_insecure = metrics.Metric(
    name="pdns_recursor_dnssec_insecure",
    title=Title("DNSSEC insecure"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.YELLOW,
)
metric_pdns_recursor_dnssec_bogus = metrics.Metric(
    name="pdns_recursor_dnssec_bogus",
    title=Title("DNSSEC bogus"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.RED,
)
metric_pdns_recursor_dnssec_bogus_perc = metrics.Metric(
    name="pdns_recursor_dnssec_bogus_perc",
    title=Title("DNSSEC bogus ratio"),
    unit=UNIT_PERCENT,
    color=metrics.Color.DARK_RED,
)
metric_pdns_recursor_dnssec_indeterminate = metrics.Metric(
    name="pdns_recursor_dnssec_indeterminate",
    title=Title("DNSSEC indeterminate"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.ORANGE,
)
metric_pdns_recursor_dnssec_nta = metrics.Metric(
    name="pdns_recursor_dnssec_nta",
    title=Title("DNSSEC negative trust anchor"),
    unit=UNIT_PER_SECOND,
    color=metrics.Color.PURPLE,
)

# --------------------------------------------------------------------------
# Graphs
# --------------------------------------------------------------------------
graph_pdns_auth_queries = graphs.Bidirectional(
    name="pdns_auth_queries",
    title=Title("PowerDNS authoritative queries and answers"),
    lower=graphs.Graph(
        name="pdns_auth_queries_in",
        title=Title("Queries"),
        compound_lines=["pdns_auth_udp_queries", "pdns_auth_tcp_queries"],
    ),
    upper=graphs.Graph(
        name="pdns_auth_answers_out",
        title=Title("Answers"),
        compound_lines=["pdns_auth_udp_answers", "pdns_auth_tcp_answers"],
    ),
)

graph_pdns_auth_problems = graphs.Graph(
    name="pdns_auth_problems",
    title=Title("PowerDNS authoritative problem packets"),
    compound_lines=[
        "pdns_auth_servfail",
        "pdns_auth_corrupt",
        "pdns_auth_timedout",
        "pdns_auth_overload_drops",
    ],
)

graph_pdns_auth_cache_ratio = graphs.Graph(
    name="pdns_auth_cache_ratio",
    title=Title("PowerDNS authoritative cache hit ratio"),
    simple_lines=["pdns_auth_packetcache_hit_ratio", "pdns_auth_querycache_hit_ratio"],
    minimal_range=graphs.MinimalRange(0, 100),
)

graph_pdns_auth_cache_size = graphs.Graph(
    name="pdns_auth_cache_size",
    title=Title("PowerDNS authoritative cache entries"),
    simple_lines=[
        "pdns_auth_packetcache_size",
        "pdns_auth_querycache_size",
        "pdns_auth_key_cache_size",
        "pdns_auth_meta_cache_size",
        "pdns_auth_signature_cache_size",
    ],
)

graph_pdns_zones_by_kind = graphs.Graph(
    name="pdns_zones_by_kind",
    title=Title("PowerDNS zones by kind"),
    compound_lines=[
        "pdns_zones_native",
        "pdns_zones_primary",
        "pdns_zones_secondary",
        "pdns_zones_producer",
        "pdns_zones_consumer",
    ],
    simple_lines=["pdns_zones", "pdns_zones_dnssec"],
)

graph_pdns_records_total = graphs.Graph(
    name="pdns_records_total",
    title=Title("PowerDNS records in all zones"),
    compound_lines=["pdns_records_total"],
)

graph_pdns_zone_records = graphs.Graph(
    name="pdns_zone_records",
    title=Title("Records in zone"),
    compound_lines=["pdns_zone_records"],
    simple_lines=["pdns_zone_rrsets"],
)

graph_pdns_recursor_questions = graphs.Bidirectional(
    name="pdns_recursor_questions",
    title=Title("PowerDNS recursor incoming and outgoing queries"),
    lower=graphs.Graph(
        name="pdns_recursor_incoming",
        title=Title("Incoming"),
        compound_lines=["pdns_recursor_questions"],
        simple_lines=["pdns_recursor_tcp_questions"],
    ),
    upper=graphs.Graph(
        name="pdns_recursor_outgoing",
        title=Title("Outgoing"),
        compound_lines=["pdns_recursor_outqueries"],
        simple_lines=["pdns_recursor_tcp_outqueries"],
    ),
)

graph_pdns_recursor_answers = graphs.Graph(
    name="pdns_recursor_answers",
    title=Title("PowerDNS recursor answers by result"),
    compound_lines=[
        "pdns_recursor_noerror_answers",
        "pdns_recursor_nxdomain_answers",
        "pdns_recursor_servfail_answers",
    ],
)

graph_pdns_recursor_answer_times = graphs.Graph(
    name="pdns_recursor_answer_times",
    title=Title("PowerDNS recursor answer time distribution"),
    compound_lines=[
        "pdns_recursor_answers_0_1",
        "pdns_recursor_answers_1_10",
        "pdns_recursor_answers_10_100",
        "pdns_recursor_answers_100_1000",
        "pdns_recursor_answers_slow",
    ],
)

graph_pdns_recursor_latency = graphs.Graph(
    name="pdns_recursor_latency",
    title=Title("PowerDNS recursor latency"),
    simple_lines=["pdns_recursor_latency", "pdns_recursor_our_latency"],
)

graph_pdns_recursor_cache_ratio = graphs.Graph(
    name="pdns_recursor_cache_ratio",
    title=Title("PowerDNS recursor cache hit ratio"),
    simple_lines=["pdns_recursor_cache_hit_ratio", "pdns_recursor_packetcache_hit_ratio"],
    minimal_range=graphs.MinimalRange(0, 100),
)

graph_pdns_recursor_cache_entries = graphs.Graph(
    name="pdns_recursor_cache_entries",
    title=Title("PowerDNS recursor cache entries"),
    compound_lines=["pdns_recursor_cache_entries", "pdns_recursor_negcache_entries"],
    simple_lines=["pdns_recursor_packetcache_entries"],
)

graph_pdns_recursor_upstream = graphs.Graph(
    name="pdns_recursor_upstream",
    title=Title("PowerDNS recursor upstream problems"),
    compound_lines=[
        "pdns_recursor_timeouts",
        "pdns_recursor_throttled_out",
        "pdns_recursor_unreachables",
    ],
    simple_lines=["pdns_recursor_failed_hosts", "pdns_recursor_throttle_entries"],
)

graph_pdns_recursor_dnssec = graphs.Graph(
    name="pdns_recursor_dnssec",
    title=Title("PowerDNS recursor DNSSEC validation results"),
    compound_lines=[
        "pdns_recursor_dnssec_secure",
        "pdns_recursor_dnssec_insecure",
        "pdns_recursor_dnssec_bogus",
        "pdns_recursor_dnssec_indeterminate",
        "pdns_recursor_dnssec_nta",
    ],
    simple_lines=["pdns_recursor_dnssec_validations"],
)

# --------------------------------------------------------------------------
# Perfometers
# --------------------------------------------------------------------------
# Checkmk shows the FIRST perfometer whose referenced metrics are all present in
# a service. Definition order therefore matters: put the preferred choice for
# each service first, and any fallback (for when the preferred metric is missing)
# after it. Because each service exposes a distinct metric set, most of these
# only ever match one service.
#
# The chosen number for each service is the one worth a glance in the service
# list, with a soft Open() upper bound so the bar scales gracefully.

# --- one service per zone: the record count (the headline metric) ---------
perfometer_pdns_zone_records = perfometers.Perfometer(
    name="pdns_zone_records",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10000)),
    segments=["pdns_zone_records"],
)

# --- PowerDNS Zones summary: signed vs unsigned, stacked on the total -----
# Upper half: the total number of zones. Lower half: how many are DNSSEC
# signed. Two bars stacked give both the size and the signing coverage at a
# glance. Both metrics are always emitted by the summary check.
perfometer_pdns_zones = perfometers.Stacked(
    name="pdns_zones",
    lower=perfometers.Perfometer(
        name="pdns_zones_dnssec",
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1000)),
        segments=["pdns_zones_dnssec"],
    ),
    upper=perfometers.Perfometer(
        name="pdns_zones_total",
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1000)),
        segments=["pdns_zones"],
    ),
)

# --- PowerDNS Auth Queries: queries in vs answers out ---------------------
perfometer_pdns_auth_queries = perfometers.Bidirectional(
    name="pdns_auth_queries",
    left=perfometers.Perfometer(
        name="pdns_auth_queries_left",
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(5000)),
        segments=["pdns_auth_udp_queries", "pdns_auth_tcp_queries"],
    ),
    right=perfometers.Perfometer(
        name="pdns_auth_answers_right",
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(5000)),
        segments=["pdns_auth_udp_answers", "pdns_auth_tcp_answers"],
    ),
)

# --- PowerDNS Auth Cache: packet cache hit ratio --------------------------
# The hit ratio is a counter rate, so on the very first check after discovery it
# is not yet available. The entry-count fallback (always present) keeps the
# service from showing a blank perfometer during that one cycle.
perfometer_pdns_auth_cache = perfometers.Perfometer(
    name="pdns_auth_packetcache_hit_ratio",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100)),
    segments=["pdns_auth_packetcache_hit_ratio"],
)
perfometer_pdns_auth_cache_size = perfometers.Perfometer(
    name="pdns_auth_packetcache_size",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(100000)),
    segments=["pdns_auth_packetcache_size"],
)

# --- PowerDNS Auth Latency ------------------------------------------------
perfometer_pdns_auth_latency = perfometers.Perfometer(
    name="pdns_auth_latency",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(0.5)),
    segments=["pdns_auth_latency"],
)

# --- PowerDNS Auth status: memory, with an FD-count fallback --------------
# The status service has no single obvious metric; resident memory is the most
# universally meaningful. If a future build ever drops the memory counter, fall
# back to the open file descriptors.
perfometer_pdns_auth_memory = perfometers.Perfometer(
    name="pdns_auth_memory",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(2147483648)),
    segments=["pdns_auth_memory"],
)
perfometer_pdns_auth_fd = perfometers.Perfometer(
    name="pdns_auth_fd_usage",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1024)),
    segments=["pdns_auth_fd_usage"],
)

# --- PowerDNS Recursor status: mthread usage %, memory fallback -----------
# mthread usage is the capacity signal (queries in flight vs max-mthreads). It
# is only present when max-mthreads is reported, so memory is the fallback.
perfometer_pdns_recursor_mthreads = perfometers.Perfometer(
    name="pdns_recursor_mthread_usage",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100)),
    segments=["pdns_recursor_mthread_usage"],
)
perfometer_pdns_recursor_memory = perfometers.Perfometer(
    name="pdns_recursor_memory",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(4294967296)),
    segments=["pdns_recursor_memory"],
)

# --- PowerDNS Recursor Queries: questions per second ----------------------
perfometer_pdns_recursor_questions = perfometers.Perfometer(
    name="pdns_recursor_questions",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10000)),
    segments=["pdns_recursor_questions"],
)

# --- PowerDNS Recursor Cache: record cache hit ratio ----------------------
# Same as the auth cache: hit ratio first, entry-count fallback for the first
# check before the rate is available.
perfometer_pdns_recursor_cache = perfometers.Perfometer(
    name="pdns_recursor_cache_hit_ratio",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Closed(100)),
    segments=["pdns_recursor_cache_hit_ratio"],
)
perfometer_pdns_recursor_cache_entries = perfometers.Perfometer(
    name="pdns_recursor_cache_entries",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1000000)),
    segments=["pdns_recursor_cache_entries"],
)

# --- PowerDNS Recursor Latency --------------------------------------------
perfometer_pdns_recursor_latency = perfometers.Perfometer(
    name="pdns_recursor_latency",
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(1)),
    segments=["pdns_recursor_latency"],
)

# --- PowerDNS Recursor DNSSEC: validation composition ---------------------
# Stack the validation outcome rates so the bar shows the mix of secure (green),
# insecure (yellow) and bogus (red) at a glance. The validations counter is
# always present when this service exists, so the composition metrics are too.
perfometer_pdns_recursor_dnssec = perfometers.Perfometer(
    name="pdns_recursor_dnssec",
    focus_range=perfometers.FocusRange(
        perfometers.Closed(0),
        perfometers.Open(1000),
    ),
    segments=[
        "pdns_recursor_dnssec_secure",
        "pdns_recursor_dnssec_insecure",
        "pdns_recursor_dnssec_bogus",
        "pdns_recursor_dnssec_indeterminate",
        "pdns_recursor_dnssec_nta",
    ],
)
