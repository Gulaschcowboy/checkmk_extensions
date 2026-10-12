#!/usr/bin/env python3
"""WATO ruleset for the XenServer / XCP-ng special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    List,
    Password,
    SingleChoice,
    SingleChoiceElement,
    String,
    migrate_to_password,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("XenServer / XCP-ng via XAPI"),
        help_text=Help(
            "Monitor a XenServer or XCP-ng pool through the XAPI management API "
            "(HTTPS, port 443). Configure this rule on a host whose IP address is "
            "the pool coordinator. Pool, shared storage repositories and alerts are "
            "reported on this host; every XenServer host and every VM is delivered "
            "as piggyback data (create the hosts manually or via the dynamic host "
            "management). The agent only reads data. A user with the role "
            "'read-only' is sufficient (requires an external directory, e.g. AD); "
            "otherwise use a pool admin / root account. The Checkmk server needs "
            "access to port 443 of every pool member, because performance data "
            "(RRD) is read from the host running the VM."
        ),
        elements={
            "user": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("User"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "password": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("Password"),
                    help_text=Help("Passed to the agent via stdin, not on the command line."),
                    migrate=migrate_to_password,
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
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    help_text=Help("Needed for the self-signed certificates XenServer "
                                   "and XCP-ng create on installation."),
                    prefill=DefaultValue(True),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Timeout per request (seconds)"),
                    prefill=DefaultValue(20),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
            ),
            "pool_members": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Failover addresses"),
                    help_text=Help(
                        "Further pool members to try if the configured address is not "
                        "reachable. Members that are not the coordinator redirect the "
                        "agent to the current coordinator automatically."
                    ),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),)),
                ),
            ),
            "host_naming": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Piggyback name of XenServer hosts"),
                    elements=[
                        SingleChoiceElement(name="name_label", title=Title("Name in XenCenter (name_label)")),
                        SingleChoiceElement(name="hostname", title=Title("Host name of the dom0")),
                    ],
                    prefill=DefaultValue("name_label"),
                ),
            ),
            "vm_naming": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Piggyback name of VMs"),
                    help_text=Help("Spaces and special characters are replaced by '_'. "
                                   "Duplicate names get the first 8 characters of the "
                                   "UUID appended."),
                    elements=[
                        SingleChoiceElement(name="name_label", title=Title("VM name")),
                        SingleChoiceElement(name="uuid", title=Title("VM UUID")),
                    ],
                    prefill=DefaultValue("name_label"),
                ),
            ),
            "alerts_hours": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Alert window (hours)"),
                    help_text=Help("Messages/alerts of the last N hours are evaluated. "
                                   "0 disables fetching alerts."),
                    prefill=DefaultValue(24),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=24 * 30),),
                ),
            ),
            "skip_vms": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Do not create piggyback data for VMs"),
                    prefill=DefaultValue(False),
                ),
            ),
        },
    )


rule_spec_xenserver = SpecialAgent(
    name="xenserver",
    title=Title("XenServer / XCP-ng (XAPI)"),
    topic=Topic.VIRTUALIZATION,
    parameter_form=_formspec,
)
