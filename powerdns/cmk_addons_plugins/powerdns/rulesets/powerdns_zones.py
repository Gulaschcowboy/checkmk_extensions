#!/usr/bin/env python3
"""Rulesets for PowerDNS zone monitoring.

Includes the discovery ruleset, which matters as soon as a server holds more
than a handful of zones: without filtering you would get one service per zone
on a machine that may host thousands.
"""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    LevelDirection,
    LevelsType,
    List,
    MatchingScope,
    MultipleChoice,
    MultipleChoiceElement,
    Percentage,
    RegularExpression,
    ServiceState,
    SimpleLevels,
    SingleChoice,
    SingleChoiceElement,
    TimeMagnitude,
    TimeSpan,
    migrate_to_float_simple_levels,
    migrate_to_integer_simple_levels,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    DiscoveryParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)

ZONE_KINDS = ("Native", "Master", "Slave", "Producer", "Consumer")


def _count_levels(
    title: Title,
    direction: LevelDirection,
    prefill: tuple[int, int] | None = None,
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        form_spec_template=Integer(),
        level_direction=direction,
        prefill_fixed_levels=(
            DefaultValue(prefill) if prefill else _hint(direction)
        ),
        prefill_levels_type=DefaultValue(LevelsType.FIXED if prefill else LevelsType.NONE),
        migrate=migrate_to_integer_simple_levels,
    )


def _hint(direction: LevelDirection):
    from cmk.rulesets.v1.form_specs import InputHint

    return InputHint((100, 200) if direction is LevelDirection.UPPER else (10, 5))


def _seconds_levels(
    title: Title,
    prefill: tuple[float, float],
    help_text: Help | None = None,
) -> SimpleLevels:
    return SimpleLevels(
        title=title,
        help_text=help_text,
        form_spec_template=TimeSpan(
            displayed_magnitudes=[
                TimeMagnitude.MINUTE,
                TimeMagnitude.HOUR,
                TimeMagnitude.DAY,
            ],
        ),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue(prefill),
        migrate=migrate_to_float_simple_levels,
    )


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------
rule_spec_discovery_powerdns_zones = DiscoveryParameters(
    name="discovery_powerdns_zones",
    title=Title("PowerDNS zone discovery"),
    topic=Topic.APPLICATIONS,
    parameter_form=lambda: Dictionary(
        help_text=Help(
            "Controls which zones become their own service. The summary service "
            "'PowerDNS Zones' is always created and is unaffected by this rule."
        ),
        elements={
            "mode": DictElement(
                parameter_form=SingleChoice(
                    title=Title("Service creation"),
                    elements=[
                        SingleChoiceElement(
                            name="per_zone",
                            title=Title("Create one service per zone"),
                        ),
                        SingleChoiceElement(
                            name="summary_only",
                            title=Title("Summary service only, no per-zone services"),
                        ),
                    ],
                    prefill=DefaultValue("per_zone"),
                ),
                required=True,
            ),
            "include": DictElement(
                parameter_form=List(
                    title=Title("Only these zones"),
                    help_text=Help(
                        "Regular expressions matched against the zone name without "
                        "the trailing dot. If empty, all zones are considered."
                    ),
                    element_template=RegularExpression(
                        predefined_help_text=MatchingScope.INFIX,
                        label=Label("Pattern"),
                    ),
                    add_element_label=Label("Add pattern"),
                ),
            ),
            "exclude": DictElement(
                parameter_form=List(
                    title=Title("Except these zones"),
                    help_text=Help(
                        "Evaluated after the include patterns. Useful for skipping "
                        "generated reverse zones, for example '\\.in-addr\\.arpa$'."
                    ),
                    element_template=RegularExpression(
                        predefined_help_text=MatchingScope.INFIX,
                        label=Label("Pattern"),
                    ),
                    add_element_label=Label("Add pattern"),
                ),
            ),
            "kinds": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Only these zone kinds"),
                    help_text=Help(
                        "If nothing is selected, all kinds are discovered. "
                        "Producer and Consumer are catalog zones."
                    ),
                    elements=[
                        MultipleChoiceElement(name=kind, title=Title(kind))  # type: ignore[arg-type]
                        for kind in ZONE_KINDS
                    ],
                ),
            ),
        },
    ),
)


# --------------------------------------------------------------------------
# Zone summary
# --------------------------------------------------------------------------
rule_spec_powerdns_zones = CheckParameters(
    name="powerdns_zones",
    title=Title("PowerDNS zone summary"),
    topic=Topic.APPLICATIONS,
    condition=HostCondition(),
    parameter_form=lambda: Dictionary(
        elements={
            "zone_count_upper": DictElement(
                parameter_form=_count_levels(
                    Title("Maximum number of zones"),
                    LevelDirection.UPPER,
                ),
            ),
            "zone_count_lower": DictElement(
                parameter_form=_count_levels(
                    Title("Minimum number of zones"),
                    LevelDirection.LOWER,
                ),
            ),
            "record_count_upper": DictElement(
                parameter_form=_count_levels(
                    Title("Maximum number of records over all zones"),
                    LevelDirection.UPPER,
                ),
            ),
            "record_count_lower": DictElement(
                parameter_form=_count_levels(
                    Title("Minimum number of records over all zones"),
                    LevelDirection.LOWER,
                ),
            ),
            "state_empty_zone": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when a zone contains no records"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "records_age": DictElement(
                parameter_form=_seconds_levels(
                    Title("Maximum age of the collected record counts"),
                    (7200.0, 21600.0),
                    Help(
                        "Record counts are refreshed on their own interval "
                        "(zone_refresh in powerdns.cfg) because counting is the "
                        "expensive part of the collection. This level warns when "
                        "the numbers behind the graph have gone stale."
                    ),
                ),
            ),
        },
    ),
)


# --------------------------------------------------------------------------
# Per zone
# --------------------------------------------------------------------------
rule_spec_powerdns_zone = CheckParameters(
    name="powerdns_zone",
    title=Title("PowerDNS single zone"),
    topic=Topic.APPLICATIONS,
    condition=HostAndItemCondition(item_title=Title("Zone")),
    parameter_form=lambda: Dictionary(
        elements={
            "records_upper": DictElement(
                parameter_form=_count_levels(
                    Title("Maximum number of records in the zone"),
                    LevelDirection.UPPER,
                ),
            ),
            "records_lower": DictElement(
                parameter_form=_count_levels(
                    Title("Minimum number of records in the zone"),
                    LevelDirection.LOWER,
                    (1, 0),
                ),
            ),
            "records_drop_perc": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Relative drop of the record count"),
                    help_text=Help(
                        "Compares the record count with the previous check. This "
                        "catches an accidentally emptied or truncated zone without "
                        "having to maintain an absolute level per zone."
                    ),
                    form_spec_template=Percentage(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((25.0, 50.0)),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "notify_lag": DictElement(
                parameter_form=_seconds_levels(
                    Title("Time the current serial may stay un-notified"),
                    (900.0, 3600.0),
                    Help(
                        "Primary zones only. Compares serial with notified_serial. "
                        "A short mismatch is normal right after an edit, so the "
                        "mismatch has to persist for this long before it is reported."
                    ),
                ),
            ),
            "last_check_age": DictElement(
                parameter_form=_seconds_levels(
                    Title("Age of the last successful check of the primary"),
                    (7200.0, 86400.0),
                    Help(
                        "Secondary zones only. Uses the last_check timestamp "
                        "maintained by PowerDNS. Set this above the SOA refresh "
                        "interval of your zones."
                    ),
                ),
            ),
            "state_never_checked": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when a secondary zone was never transferred"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_unsigned": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when the zone is not DNSSEC signed"),
                    help_text=Help(
                        "Set this to WARN on hosts where every zone is expected to "
                        "be signed, and use a more specific rule for the exceptions."
                    ),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
        },
    ),
)
