#!/usr/bin/env python3
"""WATO ruleset for the Hermes Agent dashboard special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    SingleChoice,
    SingleChoiceElement,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("Hermes Agent dashboard via REST API"),
        help_text=Help(
            "Poll a Hermes Agent web dashboard (started with 'hermes "
            "dashboard', default port 9119) over its public "
            "{GET /api/status} endpoint for gateway process state, "
            "per-platform (Telegram/Discord/Slack/...) connection status, "
            "per-component health (gateway/dashboard/storage/platforms) and "
            "active session count. The endpoint is unauthenticated by "
            "design on localhost; optional HTTP basic-auth is only needed "
            "if a reverse proxy in front of the dashboard requires it."
        ),
        elements={
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTP port"),
                    help_text=Help("TCP port of the dashboard (default 9119)."),
                    prefill=DefaultValue(9119),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "protocol": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Protocol"),
                    elements=[
                        SingleChoiceElement(name="http", title=Title("HTTP")),
                        SingleChoiceElement(name="https", title=Title("HTTPS")),
                    ],
                    prefill=DefaultValue("http"),
                ),
            ),
            "username": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("HTTP basic-auth username"),
                    help_text=Help("Only needed if a reverse proxy in front "
                                   "of the dashboard requires basic auth."),
                ),
            ),
            "password": DictElement(
                required=False,
                parameter_form=Password(
                    title=Title("HTTP basic-auth password"),
                    migrate=migrate_to_password,
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Request timeout (seconds)"),
                    prefill=DefaultValue(10),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
            ),
        },
    )


rule_spec_hermes_dashboard = SpecialAgent(
    name="hermes_dashboard",
    title=Title("Hermes Agent dashboard (REST API)"),
    topic=Topic.APPLICATIONS,
    parameter_form=_formspec,
)
