#!/usr/bin/env python3
"""WATO ruleset for the OPNsense special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.form_specs import BooleanChoice
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("OPNsense via REST API"),
        help_text=Help(
            "Poll an OPNsense firewall over its REST API for firmware "
            "update status, running services, and system diagnostics. "
            "Create an API key/secret under System > Access > Users > "
            "[user] > API keys. A read-only user with the privileges "
            "'System: Firmware', 'System: Status', 'Status: Services' and "
            "'Lobby: Dashboard' is sufficient."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API key"),
                    help_text=Help("The OPNsense API key (used as username). "
                                   "May reference the password store."),
                    migrate=migrate_to_password,
                ),
            ),
            "api_secret": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API secret"),
                    help_text=Help("The OPNsense API secret (used as password)."),
                    migrate=migrate_to_password,
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    help_text=Help("TCP port of the OPNsense web GUI / API."),
                    prefill=DefaultValue(8443),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    help_text=Help(
                        "Enable this if the OPNsense uses a self-signed "
                        "certificate (default for a fresh install)."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Request timeout (seconds)"),
                    prefill=DefaultValue(20),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
            ),
        },
    )


rule_spec_opnsense = SpecialAgent(
    name="opnsense",
    title=Title("OPNsense firewall (REST API)"),
    topic=Topic.NETWORKING,
    parameter_form=_formspec,
)
