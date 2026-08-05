#!/usr/bin/env python3
"""Check parameter rulesets for the PowerDNS Authoritative Server."""

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
        prefill_fixed_levels=(
            DefaultValue(prefill) if prefill else InputHint((1.0, 10.0))
        ),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_float_simple_levels,
    )


def _count_levels(
    title: Title,
    prefill: tuple[int, int] | None = None,
    unit: str = "",
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=Integer(unit_symbol=unit),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(prefill) if prefill else InputHint((100, 1000)),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_integer_simple_levels,
    )


def _percent_levels(
    title: Title,
    direction: LevelDirection,
    prefill: tuple[float, float] | None = None,
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=Percentage(),
        level_direction=direction,
        prefill_fixed_levels=(
            DefaultValue(prefill) if prefill else InputHint((90.0, 80.0))
        ),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_float_simple_levels,
    )


def _seconds_levels(
    title: Title,
    direction: LevelDirection,
    prefill: tuple[float, float],
    magnitudes: list[TimeMagnitude] | None = None,
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=TimeSpan(
            displayed_magnitudes=magnitudes
            or [TimeMagnitude.MILLISECOND, TimeMagnitude.SECOND],
        ),
        level_direction=direction,
        prefill_fixed_levels=DefaultValue(prefill),
        migrate=migrate_to_float_simple_levels,
    )


def _security_status_elements() -> dict[str, DictElement]:
    return {
        "state_no_status": DictElement(
            parameter_form=ServiceState(
                title=Title("State when no security status is known yet"),
                help_text=Help(
                    "PowerDNS polls secpoll.powerdns.com for known "
                    "vulnerabilities. Right after a restart, or when the poll is "
                    "disabled, no result is available yet."
                ),
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
    }


# --------------------------------------------------------------------------
rule_spec_powerdns_auth = CheckParameters(
    name="powerdns_auth",
    title=Title("PowerDNS Authoritative Server status"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        help_text=Help(
            "Parameters for the overall status of the PowerDNS Authoritative Server."
        ),
        elements={
            **_security_status_elements(),
            "uptime_min": DictElement(
                parameter_form=_seconds_levels(
                    Title("Minimum uptime (detect unexpected restarts)"),
                    LevelDirection.LOWER,
                    (600.0, 300.0),
                    [TimeMagnitude.MINUTE, TimeMagnitude.HOUR],
                ),
            ),
            "queue": DictElement(
                parameter_form=_count_levels(
                    Title("Queued questions waiting for the backend"),
                    (100, 1000),
                ),
            ),
            "memory": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Resident memory usage"),
                    form_spec_template=DataSize(
                        displayed_magnitudes=[IECMagnitude.MEBI, IECMagnitude.GIBI],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=InputHint((1073741824, 2147483648)),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    migrate=migrate_to_integer_simple_levels,
                ),
            ),
            "fd_usage": DictElement(
                parameter_form=_count_levels(Title("Open file descriptors")),
            ),
            "open_tcp_connections": DictElement(
                parameter_form=_count_levels(Title("Open TCP connections")),
            ),
        },
    ),
)

rule_spec_powerdns_auth_queries = CheckParameters(
    name="powerdns_auth_queries",
    title=Title("PowerDNS Authoritative Server query rates"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        help_text=Help(
            "All levels are evaluated against the rate of change of the "
            "respective PowerDNS counter, in events per second."
        ),
        elements={
            "servfail_perc": DictElement(
                parameter_form=_percent_levels(
                    Title("Share of queries answered with SERVFAIL"),
                    LevelDirection.UPPER,
                    (5.0, 20.0),
                ),
            ),
            "servfail": DictElement(
                parameter_form=_rate_levels(Title("SERVFAIL packets")),
            ),
            "corrupt": DictElement(
                parameter_form=_rate_levels(Title("Corrupt packets"), (1.0, 10.0)),
            ),
            "timedout": DictElement(
                parameter_form=_rate_levels(Title("Packets timed out in the backend")),
            ),
            "overload_drops": DictElement(
                parameter_form=_rate_levels(
                    Title("Queries dropped because the backend was overloaded"),
                    (0.5, 5.0),
                ),
            ),
            "udp_queries": DictElement(
                parameter_form=_rate_levels(Title("UDP queries")),
            ),
            "tcp_queries": DictElement(
                parameter_form=_rate_levels(Title("TCP queries")),
            ),
        },
    ),
)

rule_spec_powerdns_auth_cache = CheckParameters(
    name="powerdns_auth_cache",
    title=Title("PowerDNS Authoritative Server caches"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        help_text=Help(
            "Hit ratios are computed from the change of the hit and miss "
            "counters since the previous check, so they describe current "
            "behaviour rather than the average since the last restart."
        ),
        elements={
            "packetcache_hit_ratio": DictElement(
                parameter_form=_percent_levels(
                    Title("Packet cache hit ratio"),
                    LevelDirection.LOWER,
                ),
            ),
            "querycache_hit_ratio": DictElement(
                parameter_form=_percent_levels(
                    Title("Query cache hit ratio"),
                    LevelDirection.LOWER,
                ),
            ),
            "deferred_inserts": DictElement(
                parameter_form=_rate_levels(
                    Title("Deferred cache inserts (cache lock contention)"),
                    (1.0, 10.0),
                ),
            ),
            "deferred_lookups": DictElement(
                parameter_form=_rate_levels(
                    Title("Deferred cache lookups (cache lock contention)"),
                    (1.0, 10.0),
                ),
            ),
        },
    ),
)

rule_spec_powerdns_auth_latency = CheckParameters(
    name="powerdns_auth_latency",
    title=Title("PowerDNS Authoritative Server latency"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "latency": DictElement(
                parameter_form=_seconds_levels(
                    Title("Average answer latency"),
                    LevelDirection.UPPER,
                    (0.05, 0.2),
                ),
                required=True,
            ),
        },
    ),
)
