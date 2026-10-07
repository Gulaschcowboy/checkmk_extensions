#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WATO ruleset for the Citrix Virtual Apps and Desktops (CVAD) REST API special agent."""
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
        title=Title("Citrix Virtual Apps and Desktops (via REST API)"),
        help_text=Help(
            "Polls a Citrix Delivery Controller (DDC) over the on-premises CVAD REST "
            "API (Citrix Orchestration Service, requires CVAD 2212 or newer) and "
            "creates piggyback data for the Citrix VDA machines and hypervisor hosts "
            "running them. \n"
            "If your Checkmk hosts are configured with short names but Citrix reports "
            "FQDNs (or vice versa), use Checkmk's built-in ruleset 'Host name "
            "translation for piggybacked hosts' (option 'Drop domain part') on this "
            "host."
        ),
        elements={
            "ddc_address": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Delivery Controller (DDC) address"),
                    help_text=Help(
                        "FQDN or IP address of the Citrix Delivery Controller. "
                        "Leave empty to use this host's configured IP address."
                    ),
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    prefill=DefaultValue(443),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "user": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Citrix admin user"),
                    help_text=Help(
                        "Domain user with Citrix administrator role, e.g. "
                        "DOMAIN\\\\svc_checkmk. A Read-Only Administrator role is "
                        "sufficient for monitoring."
                    ),
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
                    help_text=Help("Enable this if the DDC uses a self-signed certificate."),
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
            "max_machines": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Maximum number of machines to fetch"),
                    help_text=Help("Safety limit, mirrors the $maxmachines setting of citrix_farm.ps1."),
                    prefill=DefaultValue(2000),
                    custom_validate=(validators.NumberInRange(min_value=1),),
                ),
            ),
            "max_sessions": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Maximum number of sessions to fetch"),
                    help_text=Help("Safety limit, mirrors the $maxusers setting of citrix_farm.ps1."),
                    prefill=DefaultValue(10000),
                    custom_validate=(validators.NumberInRange(min_value=1),),
                ),
            ),
            "no_hostsystem": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Do not create Citrix Host Info/VMs services on hypervisor hosts"),
                    label=Label("Skip citrix_hostsystem piggyback data"),
                    help_text=Help(
                        "Enable this if hypervisor hosts are already piggybacked from "
                        "elsewhere (e.g. vSphere/Proxmox special agents) and you do "
                        "not want an additional Citrix Host Info/VMs service there."
                    ),
                    prefill=DefaultValue(False),
                ),
            ),
        },
    )


rule_spec_citrix_ddc_rest = SpecialAgent(
    name="citrix_ddc_rest",
    title=Title("Citrix Virtual Apps and Desktops (via REST API)"),
    topic=Topic.VIRTUALIZATION,
    parameter_form=_formspec,
)
