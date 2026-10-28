#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery ruleset for the "sshd_crypto" agent plug-in.

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _migrate(value: object) -> Mapping[str, object]:
    if isinstance(value, dict) and "deployment" in value:
        return value
    return {"deployment": ("sync" if value else "do_not_deploy", None)}


def _form_spec_agent_config_sshd_crypto() -> Dictionary:
    return Dictionary(
        migrate=_migrate,
        help_text=Help(
            "Deploys the agent plug-in <tt>sshd_crypto</tt>. It reports the key "
            "exchange algorithms, ciphers, MACs, host key and public key algorithms "
            "offered by the local OpenSSH daemon (<tt>sshd -T</tt>). On hosts "
            "without <tt>sshd</tt> it prints nothing, so no service is discovered "
            "there. The configuration only changes on sshd reconfiguration or "
            "package updates, so asynchronous execution (e.g. every hour) is "
            "perfectly fine."
        ),
        elements={
            "deployment": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Deployment type"),
                    elements=(
                        CascadingSingleChoiceElement(
                            name="sync",
                            title=Title("Deploy the plug-in and run it synchronously"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="cached",
                            title=Title("Deploy the plug-in and run it asynchronously"),
                            parameter_form=TimeSpan(
                                displayed_magnitudes=(
                                    TimeMagnitude.HOUR,
                                    TimeMagnitude.MINUTE,
                                ),
                                prefill=DefaultValue(3600.0),
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="do_not_deploy",
                            title=Title("Do not deploy the plug-in"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ),
                    prefill=DefaultValue("sync"),
                ),
            ),
        },
    )


rule_spec_agent_config_sshd_crypto = AgentConfig(
    title=Title("SSH daemon crypto algorithms (Linux)"),
    name="sshd_crypto",
    topic=Topic.APPLICATIONS,
    parameter_form=_form_spec_agent_config_sshd_crypto,
)
