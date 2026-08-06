#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery ruleset for the "proxmox_node_swap" agent plug-in.
# Decides whether the plug-in is deployed to Linux/Proxmox agents.

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def migrate_bakery_rule(value: object) -> Mapping[str, object]:
    """Normalise to {"deploy": bool}, dropping any legacy caching config."""
    match value:
        case bool(deploy):
            return {"deploy": deploy}
        case None:
            return {"deploy": False}
        case dict() as d if "deploy" in d:
            return {"deploy": bool(d["deploy"])}
        case dict():
            return {"deploy": True}
    raise ValueError(value)


def _form_spec_agent_config_proxmox_node_swap() -> Dictionary:
    return Dictionary(
        migrate=migrate_bakery_rule,
        help_text=Help(
            "This will deploy the agent plug-in <tt>proxmox_node_swap</tt> for "
            "monitoring node swap usage and the top swap-consuming guests on a "
            "Proxmox VE node. The plug-in runs synchronously with each agent "
            "run (no caching)."
        ),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    label=Label("Deploy the Proxmox node swap plug-in"),
                    prefill=DefaultValue(True),
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
