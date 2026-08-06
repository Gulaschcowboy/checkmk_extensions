#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Check parameters for "Proxmox Node Swap Usage": warn/crit on percent swap used.

from collections.abc import Mapping

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    LevelDirection,
    SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _migrate(value: object) -> Mapping[str, object]:
    """Accept both the modern SimpleLevels form and the legacy bare tuple.

    SimpleLevels stores ``("fixed", (warn, crit))`` or ``("no_levels", None)``.
    Older rules (and the pre-2.0 default) stored a bare ``(warn, crit)`` tuple,
    which WATO rejects as "Invalid check parameter: (50.0, 80.0)".
    """
    if not isinstance(value, dict):
        return {"levels": ("fixed", (50.0, 80.0))}
    lv = value.get("levels")
    # already in SimpleLevels form -> keep as-is
    if isinstance(lv, (tuple, list)) and len(lv) == 2 and lv[0] in ("fixed", "no_levels"):
        return {**value, "levels": tuple(lv)}
    # legacy bare (warn, crit) tuple -> wrap
    if isinstance(lv, (tuple, list)) and len(lv) == 2 and all(
        isinstance(x, (int, float)) for x in lv
    ):
        return {**value, "levels": ("fixed", (float(lv[0]), float(lv[1])))}
    # None / missing / anything else -> no levels
    return {**value, "levels": ("no_levels", None)}


def _form_spec_proxmox_node_swap() -> Dictionary:
    return Dictionary(
        migrate=_migrate,
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
