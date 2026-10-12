#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WATO check parameter rulesets for the LinOTP REST checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    InputHint,
    LevelDirection,
    LevelsType,
    ServiceState,
    SimpleLevels,
    migrate_to_float_simple_levels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, HostCondition, Topic


def _resolvers_form():
    return Dictionary(
        elements={
            "levels_lower_total_users": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Lower levels for configured users"),
                    help_text=Help(
                        "A resolver suddenly reporting fewer configured users than this "
                        "usually means its LDAP/SQL backend became unreachable or "
                        "misconfigured. Default: WARN below 1 (i.e. an empty resolver)."
                    ),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((1.0, 0.0)),
                ),
            ),
            "levels_upper_total_users": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels for configured users"),
                    help_text=Help(
                        "Alert when a resolver reports more configured users than "
                        "expected, e.g. to catch unexpected bulk imports. No upper "
                        "levels are set by default."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=InputHint((1000.0, 2000.0)),
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
        }
    )


rule_spec_linotp_rest_resolvers = CheckParameters(
    name="linotp_rest_resolvers",
    title=Title("LinOTP resolver user counts"),
    topic=Topic.APPLICATIONS,
    parameter_form=_resolvers_form,
    condition=HostAndItemCondition(item_title=Title("Realm / resolver")),
)


def _levels_dict_element(title: Title, help_text: Help, direction: LevelDirection) -> DictElement:
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            help_text=help_text,
            level_direction=direction,
            form_spec_template=Float(),
            prefill_fixed_levels=InputHint((100.0, 200.0) if direction is LevelDirection.UPPER else (10.0, 5.0)),
            prefill_levels_type=DefaultValue(LevelsType.NONE),
            migrate=migrate_to_float_simple_levels,
        ),
    )


def _tokens_form():
    return Dictionary(
        elements={
            "levels_lower_total": _levels_dict_element(
                Title("Lower levels for total tokens"),
                Help(
                    "Alert when the number of tokens in this realm drops below this "
                    "level, e.g. after unexpected bulk revocation. No lower levels "
                    "are set by default."
                ),
                LevelDirection.LOWER,
            ),
            "levels_upper_total": _levels_dict_element(
                Title("Upper levels for total tokens"),
                Help(
                    "Alert when the number of tokens in this realm exceeds this "
                    "level, e.g. to get an early warning before a license limit is "
                    "reached. No upper levels are set by default."
                ),
                LevelDirection.UPPER,
            ),
            "levels_lower_total_users": _levels_dict_element(
                Title("Lower levels for users with tokens"),
                Help(
                    "Alert when the number of users with at least one token in "
                    "this realm drops below this level. No lower levels are set "
                    "by default."
                ),
                LevelDirection.LOWER,
            ),
            "levels_upper_total_users": _levels_dict_element(
                Title("Upper levels for users with tokens"),
                Help(
                    "Alert when the number of users with at least one token in "
                    "this realm exceeds this level. No upper levels are set by "
                    "default."
                ),
                LevelDirection.UPPER,
            ),
        }
    )


rule_spec_linotp_rest_tokens = CheckParameters(
    name="linotp_rest_tokens",
    title=Title("LinOTP token counts"),
    topic=Topic.APPLICATIONS,
    parameter_form=_tokens_form,
    condition=HostAndItemCondition(item_title=Title("Realm")),
)


def _config_form():
    return Dictionary(
        elements={
            "state_not_in_sync": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when LinOTP config is not in sync across nodes"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        }
    )


rule_spec_linotp_rest_config = CheckParameters(
    name="linotp_rest_config",
    title=Title("LinOTP config sync status"),
    topic=Topic.APPLICATIONS,
    parameter_form=_config_form,
    condition=HostCondition(),
)
