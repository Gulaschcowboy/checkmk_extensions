#!/usr/bin/env python3
"""Agent Bakery ruleset for the agent-based PowerDNS package.

Rule name ``powerdns`` matches the bakery plugin. Because this package keeps
thresholds and zone discovery in the regular WATO check rulesets, this rule only
covers deployment, the optional cache interval, and the connection/record-count
settings that make up /etc/check_mk/powerdns.cfg.
"""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    SingleChoice,
    SingleChoiceElement,
    String,
    TimeMagnitude,
    TimeSpan,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _config() -> Dictionary:
    return Dictionary(
        title=Title("Deploy a configuration file"),
        help_text=Help(
            "When set, the bakery writes /etc/check_mk/powerdns.cfg from these "
            "values. Leave the section off to deploy the plugin without a config "
            "file and let it auto-detect the API and key from the PowerDNS "
            "configuration on the host. Thresholds and zone-discovery filtering "
            "are configured separately in the PowerDNS check and discovery rules."
        ),
        elements={
            "auth_url": DictElement(parameter_form=String(
                title=Title("Authoritative API URL"),
                help_text=Help("e.g. http://127.0.0.1:8081; empty = autodetect"),
            )),
            "auth_api_key": DictElement(parameter_form=Password(
                title=Title("Authoritative API key"),
                migrate=migrate_to_password,
            )),
            "recursor_url": DictElement(parameter_form=String(
                title=Title("Recursor API URL"),
                help_text=Help("e.g. http://127.0.0.1:8082; empty = autodetect"),
            )),
            "recursor_api_key": DictElement(parameter_form=Password(
                title=Title("Recursor API key"),
                migrate=migrate_to_password,
            )),
            "zones": DictElement(parameter_form=BooleanChoice(
                title=Title("Collect the zone inventory"),
                prefill=DefaultValue(True),
            )),
            "zone_refresh": DictElement(parameter_form=TimeSpan(
                title=Title("Record-count refresh interval"),
                displayed_magnitudes=[TimeMagnitude.MINUTE, TimeMagnitude.HOUR],
                prefill=DefaultValue(900.0),
            )),
            "records": DictElement(parameter_form=SingleChoice(
                title=Title("Record counting mode"),
                elements=[
                    SingleChoiceElement(name="auto", title=Title("Automatic (cheap, with fallback)")),
                    SingleChoiceElement(name="count_param", title=Title("Count parameter only")),
                    SingleChoiceElement(name="full", title=Title("Full fetch (also counts RRsets)")),
                    SingleChoiceElement(name="none", title=Title("Do not count records")),
                ],
                prefill=DefaultValue("auto"),
            )),
            "max_zones": DictElement(parameter_form=Integer(
                title=Title("Maximum number of zones to process"),
                prefill=DefaultValue(2000),
            )),
        },
    )


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("PowerDNS (agent-based)"),
        help_text=Help(
            "Deploy the agent-based PowerDNS plugin. The Agent Bakery is only "
            "available in the commercial editions."
        ),
        elements={
            "deploy": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Deploy the PowerDNS plugin"),
                    label=Label("Deploy the plugin to this host"),
                    prefill=DefaultValue(True),
                ),
                required=True,
            ),
            "interval": DictElement(parameter_form=TimeSpan(
                title=Title("Run asynchronously with this cache interval"),
                help_text=Help(
                    "If set, the agent caches the plugin output for this long "
                    "instead of running it every check. Recommended on hosts "
                    "with many zones."
                ),
                displayed_magnitudes=[TimeMagnitude.SECOND, TimeMagnitude.MINUTE],
                prefill=DefaultValue(300.0),
            )),
            "config": DictElement(parameter_form=_config()),
        },
    )


rule_spec_powerdns_bakery = AgentConfig(
    name="powerdns",
    title=Title("PowerDNS (agent-based)"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)
