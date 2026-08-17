#!/usr/bin/env python3
# Agent Bakery rule for the optional Monitoring Compliance agent plug-ins.
# Appears under Setup > Agents > ... > Agent rules (commercial editions).
#
# NOTE: bakery rulesets must use a top-level Dictionary (dict value); the
# bakery framework merges parameters as a mapping.

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _form():
    return Dictionary(
        title=Title("Checkmk Monitoring Compliance (agent plug-in)"),
        help_text=Help(
            "Deploys the optional Monitoring Compliance agent plug-in (Linux "
            "shell / Windows PowerShell). It provides a clean capability "
            "section with running processes, services and installed packages. "
            "The plug-in is optional; without it the check falls back to the "
            "standard ps / lnx_packages / systemd_units / win_reg_uninstall "
            "sections."
        ),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Deployment"),
                    label=Label("Deploy the Monitoring Compliance agent plug-in"),
                    prefill=DefaultValue(True),
                ),
            ),
            "interval": DictElement(
                parameter_form=TimeSpan(
                    title=Title("Run asynchronously and cache for"),
                    help_text=Help(
                        "If set, the plug-in runs asynchronously and its "
                        "output is cached for this time."),
                    displayed_magnitudes=[
                        TimeMagnitude.HOUR,
                        TimeMagnitude.MINUTE,
                    ],
                ),
            ),
        },
    )


rule_spec_monitoring_compliance_bakery = AgentConfig(
    name="monitoring_compliance",
    title=Title("Checkmk Monitoring Compliance (agent plug-in)"),
    topic=Topic.APPLICATIONS,
    parameter_form=_form,
)
