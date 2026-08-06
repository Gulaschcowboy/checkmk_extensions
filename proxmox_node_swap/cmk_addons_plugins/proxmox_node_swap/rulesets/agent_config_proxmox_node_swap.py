#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery ruleset for the "proxmox_node_swap" agent plug-in.
# Decides whether (and how) the plug-in is deployed to Linux/Proxmox agents.

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
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


def migrate_bakery_rule(value: object) -> Mapping[str, object]:
    match value:
        case bool(deploy):
            return {"deploy": deploy, "interval": ("cached", 60.0)}
        case None:
            return {"deploy": False, "interval": ("cached", 60.0)}
        case dict() as d if "deploy" in d:
            return d
        case dict():
            return {"deploy": True, **value}
    raise ValueError(value)


def _form_spec_agent_config_proxmox_node_swap() -> Dictionary:
    return Dictionary(
        migrate=migrate_bakery_rule,
        help_text=Help(
            "This will deploy the agent plug-in <tt>proxmox_node_swap</tt> for "
            "monitoring node swap usage and the top swap-consuming guests on a "
            "Proxmox VE node. The plug-in can be run synchronously or "
            "asynchronously (cached) in the background."
        ),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    label=Label("Deploy the Proxmox node swap plug-in"),
                    prefill=DefaultValue(True),
                ),
            ),
            "interval": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Synchronicity / caching"),
                    prefill=DefaultValue("cached"),
                    elements=(
                        CascadingSingleChoiceElement(
                            name="uncached",
                            title=Title("Run synchronously"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="cached",
                            title=Title("Run asynchronously (cached)"),
                            parameter_form=TimeSpan(
                                label=Label("Collection interval"),
                                displayed_magnitudes=[
                                    TimeMagnitude.MINUTE,
                                    TimeMagnitude.SECOND,
                                ],
                                prefill=DefaultValue(60.0),
                            ),
                        ),
                    ),
                ),
            ),
        },
    )


rule_spec_agent_config_proxmox_node_swap = AgentConfig(
    title=Title("Proxmox node swap (Linux)"),
    name="proxmox_node_swap",
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_form_spec_agent_config_proxmox_node_swap,
)
