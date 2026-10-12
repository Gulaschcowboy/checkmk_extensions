#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WATO ruleset for the LinOTP REST API special agent."""
from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    String,
    migrate_to_password,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("LinOTP (via REST API)"),
        help_text=Help(
            "Monitors a LinOTP two-factor authentication server over its JSONRPC "
            "admin/monitoring API: token counts, per-resolver user counts, "
            "storage encryption, config sync and license/support status. "
            "One service per realm (and per realm/resolver) is created "
            "directly on this host."
        ),
        elements={
            "url": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Base URL"),
                    help_text=Help(
                        "Full base URL of the LinOTP instance, e.g. https://linotp.example.com "
                        "(no trailing slash, no path)."
                    ),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "user": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("LinOTP admin user"),
                    help_text=Help("A read-only admin account is sufficient for monitoring."),
                ),
            ),
            "password": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("Password"),
                    help_text=Help("The user's password. The Checkmk password store can be used."),
                    migrate=migrate_to_password,
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    label=Label("SSL certificate validation is disabled"),
                    help_text=Help("Enable this if LinOTP uses a self-signed certificate."),
                    prefill=DefaultValue(True),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Request timeout (seconds)"),
                    prefill=DefaultValue(15),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
            ),
        },
    )


rule_spec_linotp_rest = SpecialAgent(
    name="linotp_rest",
    title=Title("LinOTP (via REST API)"),
    topic=Topic.APPLICATIONS,
    parameter_form=_formspec,
)
