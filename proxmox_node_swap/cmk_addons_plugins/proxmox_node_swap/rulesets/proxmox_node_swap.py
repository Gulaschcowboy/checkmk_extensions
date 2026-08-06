#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Check parameters for "Proxmox Node Swap Usage": warn/crit on percent swap used.

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    LevelDirection,
    SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _form_spec_proxmox_node_swap() -> Dictionary:
    return Dictionary(
        elements={
            "levels": DictElement(
                required=True,
                parameter_form=SimpleLevels[float](
                    title=Title("Levels on node swap used"),
                    help_text=Help(
                        "Warning/critical levels on the percentage of the "
                        "Proxmox node's total swap that is currently in use. "
                        "Choose 'No levels' to always report OK."
                    ),
                    form_spec_template=Float(unit_symbol="%"),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((50.0, 80.0)),
                ),
            ),
        },
    )


rule_spec_proxmox_node_swap = CheckParameters(
    title=Title("Proxmox node swap usage"),
    name="proxmox_node_swap",
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_form_spec_proxmox_node_swap,
    condition=HostCondition(),
)
