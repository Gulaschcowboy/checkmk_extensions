#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Special agent ruleset for 'dnssec_health' (Setup > Agents > Other integrations)."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    InputHint,
    List,
    String,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _parameter_form() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "Monitor the DNSSEC status of DNSSEC-enabled domains. "
            "Each configured domain is checked against every configured DNS "
            "server, and a separate 'DNSSEC <domain> via <resolver>' service is "
            "created per domain/resolver combination. Each service reports "
            "whether the domain is signed (DNSKEY present) and whether that "
            "resolver validated the signatures (AD bit). This verifies both that "
            "a domain is DNSSEC-signed and that each resolver actually validates. "
            "Data is collected via DNS queries from the Checkmk site; no agent "
            "needs to be installed."
        ),
        elements={
            "domains": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Domains to check"),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                        prefill=InputHint("example.com"),
                    ),
                    add_element_label=Label("Add domain"),
                ),
            ),
            "nameservers": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("DNS servers to use"),
                    help_text=Help(
                        "IP addresses of the recursive DNS servers to query. Use a "
                        "validating resolver so the 'validated' (AD bit) result is "
                        "meaningful. If empty, the resolvers from the Checkmk server's "
                        "/etc/resolv.conf are used."
                    ),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                        prefill=InputHint("192.168.1.53"),
                    ),
                    add_element_label=Label("Add DNS server"),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Float(
                    title=Title("Timeout per DNS query (seconds)"),
                    prefill=DefaultValue(5.0),
                    custom_validate=(validators.NumberInRange(min_value=0.5, max_value=60.0),),
                ),
            ),
        },
    )


rule_spec_special_agent_dnssec_health = SpecialAgent(
    name="dnssec_health",
    title=Title("DNSSEC status"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)
