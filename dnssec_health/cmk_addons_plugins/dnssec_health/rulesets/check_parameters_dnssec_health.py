#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Check parameter ruleset for the dnssec_health service."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import DefaultValue, DictElement, Dictionary, ServiceState
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "state_unsigned": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the domain is not DNSSEC-signed"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_not_validated": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if signed but not validated by the resolver"),
                    help_text=Help(
                        "The domain publishes DNSKEY records but the resolver did not "
                        "set the AD bit. Usually means the Checkmk server's resolver "
                        "does not perform DNSSEC validation."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_dnssec_health = CheckParameters(
    name="dnssec_health",
    title=Title("DNSSEC status"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
    condition=HostAndItemCondition(item_title=Title("Domain via resolver")),
)
