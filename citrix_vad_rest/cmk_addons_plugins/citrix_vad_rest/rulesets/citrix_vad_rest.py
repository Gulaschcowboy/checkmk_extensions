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
        title=Title("Citrix Virtual Apps and Desktops (CVAD REST API)"),
        help_text=Help(
            "Poll a Citrix Delivery Controller (DDC) over the on-premises CVAD REST "
            "API (Citrix Orchestration Service, requires CVAD 2212 or newer) and "
            "create piggyback hosts for the Citrix VDA machines and hypervisor hosts, "
            "using the exact same agent sections (citrix_state, citrix_serverload, "
            "citrix_sessions, citrix_hostsystem) that Citrix's own Windows agent "
            "plug-in citrix_farm.ps1 produces. This means Checkmk's built-in Citrix "
            "checks are used unchanged -- this package ships no custom check plug-ins "
            "of its own, so there is no collision with Checkmk's built-in Citrix "
            "monitoring at the check-plug-in level. "
            "Do not run this special agent and citrix_farm.ps1 for the same machines "
            "at the same time. "
            "Limitation: the CVAD REST API has no documented equivalent for "
            "Get-BrokerController, so controller health/licensing (citrix_controller "
            "service) cannot be populated this way and still requires citrix_farm.ps1 "
            "on the DDC if needed. "
            "Create a dedicated Citrix administrator account (Read-Only Administrator "
            "role is sufficient) for the user/password below."
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
            "strip_domain_suffix": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("DNS domain suffix to strip from piggyback host names"),
                    help_text=Help(
                        "Optional, e.g. .corp.example.com. Mirrors the $DNSdomain "
                        "setting of citrix_farm.ps1, so generated piggyback host "
                        "names match your existing Checkmk host names."
                    ),
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


rule_spec_citrix_vad_rest = SpecialAgent(
    name="citrix_vad_rest",
    title=Title("Citrix Virtual Apps and Desktops (CVAD REST API)"),
    topic=Topic.VIRTUALIZATION,
    parameter_form=_formspec,
)
