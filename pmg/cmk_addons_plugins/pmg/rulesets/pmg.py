#!/usr/bin/env python3
"""WATO ruleset for the Proxmox Mail Gateway (PMG) special agent."""
from cmk.rulesets.v1 import Help, Label, Title
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
        title=Title("Proxmox Mail Gateway via REST API"),
        help_text=Help(
            "Poll a Proxmox Mail Gateway (PMG) instance over its REST API "
            "for mail statistics, Postfix queue depths, spam/virus "
            "quarantine status, ClamAV/SpamAssassin update status, node "
            "status, subscription status, pending package updates and "
            "certificate expiry. "
            "Unlike Proxmox VE, PMG has no API-token mechanism -- "
            "authentication uses a ticket obtained via username/password "
            "(POST /access/ticket). Create a dedicated, unprivileged user "
            "with role 'Audit' under User Management for monitoring."
        ),
        elements={
            "username": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Username"),
                    help_text=Help("PMG username, e.g. 'checkmk' (without realm)."),
                ),
            ),
            "password": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("Password"),
                    help_text=Help("The user's password. May reference the "
                                   "password store."),
                    migrate=migrate_to_password,
                ),
            ),
            "realm": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Authentication realm"),
                    help_text=Help("PMG realm the user belongs to, e.g. "
                                   "'pmg' (local) or 'pam'."),
                    prefill=DefaultValue("pmg"),
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    help_text=Help("TCP port of the PMG web GUI / API. "
                                   "PMG hard-codes this to 8006."),
                    prefill=DefaultValue(8006),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    label=Label("SSL certificate validation is disabled"),
                    help_text=Help(
                        "Enable this if PMG uses a self-signed certificate "
                        "(default for a fresh install)."
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
            "quarantine_lookback_days": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Fetch quarantine queue mails from the last ... days"),
                    help_text=Help(
                        "Lookback window for the spam/virus/attachment "
                        "quarantine queue services (current backlog still "
                        "needing release/delete). Does not affect the "
                        "\"...Quarantine Statistics\" services, which "
                        "always report the full quarantine database."
                    ),
                    prefill=DefaultValue(30),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=365),),
                ),
            ),
        },
    )


rule_spec_pmg = SpecialAgent(
    name="pmg",
    title=Title("Proxmox Mail Gateway (REST API)"),
    topic=Topic.NETWORKING,
    parameter_form=_formspec,
)
