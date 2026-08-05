#!/usr/bin/env python3
"""Check parameter rulesets for the PowerDNS Recursor."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DataSize,
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    IECMagnitude,
    InputHint,
    Integer,
    LevelDirection,
    LevelsType,
    Percentage,
    ServiceState,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
    migrate_to_float_simple_levels,
    migrate_to_integer_simple_levels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _rate_levels(title: Title, prefill: tuple[float, float] | None = None) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=Float(unit_symbol="/s"),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(prefill) if prefill else InputHint((1.0, 10.0)),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_float_simple_levels,
    )


def _count_levels(title: Title, prefill: tuple[int, int] | None = None) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=Integer(),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(prefill) if prefill else InputHint((100, 1000)),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_integer_simple_levels,
    )


def _percent_levels(
    title: Title,
    direction: LevelDirection,
    prefill: tuple[float, float] | None = None,
    help_text: Help | None = None,
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        help_text=help_text,
        form_spec_template=Percentage(),
        level_direction=direction,
        prefill_fixed_levels=DefaultValue(prefill) if prefill else InputHint((90.0, 80.0)),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_float_simple_levels,
    )


def _seconds_levels(title: Title, prefill: tuple[float, float]) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=TimeSpan(
            displayed_magnitudes=[TimeMagnitude.MILLISECOND, TimeMagnitude.SECOND],
        ),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(prefill),
        migrate=migrate_to_float_simple_levels,
    )


# --------------------------------------------------------------------------
rule_spec_powerdns_recursor = CheckParameters(
    name="powerdns_recursor",
    title=Title("PowerDNS Recursor status"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "state_no_status": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when no security status is known yet"),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
            "state_upgrade_recommended": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when an upgrade is recommended"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_upgrade_mandatory": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when an upgrade is mandatory (security issue)"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "uptime_min": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Minimum uptime (detect unexpected restarts)"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.MINUTE, TimeMagnitude.HOUR],
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue((600.0, 300.0)),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "concurrent_queries": DictElement(
                parameter_form=_count_levels(Title("Concurrent queries in flight")),
            ),
            "mthread_usage": DictElement(
                parameter_form=_percent_levels(
                    Title("Concurrent queries relative to max-mthreads"),
                    LevelDirection.UPPER,
                    (70.0, 90.0),
                    Help(
                        "Once this reaches 100 percent the recursor starts dropping "
                        "queries with 'over-capacity-drops'. Raise max-mthreads "
                        "before that happens."
                    ),
                ),
            ),
            "tcp_clients": DictElement(
                parameter_form=_count_levels(Title("Connected TCP clients")),
            ),
            "fd_usage": DictElement(
                parameter_form=_count_levels(Title("Open file descriptors")),
            ),
            "memory": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Resident memory usage"),
                    form_spec_template=DataSize(
                        displayed_magnitudes=[IECMagnitude.MEBI, IECMagnitude.GIBI],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((2147483648, 4294967296)),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    migrate=migrate_to_integer_simple_levels,
                ),
            ),
        },
    ),
)

rule_spec_powerdns_recursor_queries = CheckParameters(
    name="powerdns_recursor_queries",
    title=Title("PowerDNS Recursor query rates"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "servfail_perc": DictElement(
                parameter_form=_percent_levels(
                    Title("Share of questions answered with SERVFAIL"),
                    LevelDirection.UPPER,
                    (5.0, 20.0),
                ),
            ),
            "servfail": DictElement(
                parameter_form=_rate_levels(Title("SERVFAIL answers")),
            ),
            "timeouts": DictElement(
                parameter_form=_rate_levels(Title("Outgoing queries that timed out")),
            ),
            "throttled": DictElement(
                parameter_form=_rate_levels(Title("Throttled outgoing queries")),
            ),
            "unreachables": DictElement(
                parameter_form=_rate_levels(Title("Unreachable authoritative servers")),
            ),
            "drops": DictElement(
                parameter_form=_rate_levels(
                    Title("Dropped queries (over capacity, resource limits)"),
                    (0.5, 5.0),
                ),
            ),
        },
    ),
)

rule_spec_powerdns_recursor_cache = CheckParameters(
    name="powerdns_recursor_cache",
    title=Title("PowerDNS Recursor caches"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "cache_hit_ratio": DictElement(
                parameter_form=_percent_levels(
                    Title("Record cache hit ratio"),
                    LevelDirection.LOWER,
                ),
            ),
            "packetcache_hit_ratio": DictElement(
                parameter_form=_percent_levels(
                    Title("Packet cache hit ratio"),
                    LevelDirection.LOWER,
                ),
            ),
            "cache_usage": DictElement(
                parameter_form=_percent_levels(
                    Title("Record cache fill level relative to max-cache-entries"),
                    LevelDirection.UPPER,
                    (90.0, 98.0),
                ),
            ),
            "throttle_entries": DictElement(
                parameter_form=_count_levels(Title("Currently throttled nameservers")),
            ),
            "failed_hosts": DictElement(
                parameter_form=_count_levels(Title("Nameservers in the failure cache")),
            ),
        },
    ),
)

rule_spec_powerdns_recursor_latency = CheckParameters(
    name="powerdns_recursor_latency",
    title=Title("PowerDNS Recursor latency"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "latency": DictElement(
                parameter_form=_seconds_levels(
                    Title("Average question-answer latency"),
                    (0.1, 0.5),
                ),
                required=True,
            ),
            "slow_perc": DictElement(
                parameter_form=_percent_levels(
                    Title("Share of answers slower than 100 ms"),
                    LevelDirection.UPPER,
                    (10.0, 25.0),
                ),
                required=True,
            ),
        },
    ),
)

rule_spec_powerdns_recursor_dnssec = CheckParameters(
    name="powerdns_recursor_dnssec",
    title=Title("PowerDNS Recursor DNSSEC validation"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "bogus_perc": DictElement(
                parameter_form=_percent_levels(
                    Title("Share of validations resulting in bogus"),
                    LevelDirection.UPPER,
                    (1.0, 5.0),
                    Help(
                        "A rising bogus share usually means a zone somewhere "
                        "botched a key rollover, but a sustained high value can "
                        "also indicate a middlebox mangling DNSSEC responses."
                    ),
                ),
            ),
            "validations": DictElement(
                parameter_form=_rate_levels(Title("DNSSEC validations")),
            ),
        },
    ),
)
