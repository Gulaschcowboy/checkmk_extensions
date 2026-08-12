#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery ruleset for the "zfs_arc" agent plug-in.
# Decides whether the plug-in is deployed to Linux agents.

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
    """Normalise to {"deploy": bool}."""
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


def _form_spec_agent_config_zfs_arc() -> Dictionary:
    return Dictionary(
        migrate=migrate_bakery_rule,
        help_text=Help(
            "This will deploy the agent plug-in <tt>zfs_arc</tt> for monitoring "
            "ZFS ARC cache usage. The plug-in reads "
            "<tt>/proc/spl/kstat/zfs/arcstats</tt> and <tt>/proc/meminfo</tt> "
            "and emits raw numbers only; it prints nothing on a host without a "
            "ZFS ARC, so no service is discovered there. Runs synchronously "
            "with each agent run (no caching)."
        ),
        elements={
            "deploy": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    label=Label("Deploy the ZFS ARC plug-in"),
                    prefill=DefaultValue(True),
                ),
            ),
        },
    )


rule_spec_agent_config_zfs_arc = AgentConfig(
    title=Title("ZFS ARC cache usage (OpenZFS on Linux)"),
    name="zfs_arc",
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_form_spec_agent_config_zfs_arc,
)
