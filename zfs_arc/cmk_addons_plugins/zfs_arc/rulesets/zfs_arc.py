#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Check parameters for "ZFS ARC cache usage": levels on ARC-vs-max %,
# ARC-vs-RAM % and (inverted) hit ratio %.

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

_DEFAULTS = {
    "levels_arc_pct": (90.0, 97.0),
    "levels_ram_pct": (80.0, 90.0),
    "levels_hit_ratio": (85.0, 75.0),
}


def _migrate_levels(value, key):
    """Accept both the SimpleLevels form and a legacy bare tuple for one key."""
    if not isinstance(value, dict):
        return ("fixed", _DEFAULTS[key])
    lv = value.get(key)
    if isinstance(lv, (tuple, list)) and len(lv) == 2 and lv[0] in ("fixed", "no_levels"):
        return tuple(lv)
    if isinstance(lv, (tuple, list)) and len(lv) == 2 and all(
        isinstance(x, (int, float)) for x in lv
    ):
        return ("fixed", (float(lv[0]), float(lv[1])))
    return ("fixed", _DEFAULTS[key])


def _migrate(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        return {k: ("fixed", v) for k, v in _DEFAULTS.items()}
    return {
        "levels_arc_pct": _migrate_levels(value, "levels_arc_pct"),
        "levels_ram_pct": _migrate_levels(value, "levels_ram_pct"),
        "levels_hit_ratio": _migrate_levels(value, "levels_hit_ratio"),
    }


def _form_spec_zfs_arc() -> Dictionary:
    return Dictionary(
        migrate=_migrate,
        elements={
            "levels_arc_pct": DictElement(
                required=True,
                parameter_form=SimpleLevels[float](
                    title=Title("Levels on ARC size vs. zfs_arc_max"),
                    help_text=Help(
                        "Warning/critical levels on the percentage of "
                        "zfs_arc_max the ARC is currently using."
                    ),
                    form_spec_template=Float(unit_symbol="%"),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(_DEFAULTS["levels_arc_pct"]),
                ),
            ),
            "levels_ram_pct": DictElement(
                required=True,
                parameter_form=SimpleLevels[float](
                    title=Title("Levels on ARC size vs. total RAM"),
                    help_text=Help(
                        "Warning/critical levels on the percentage of total "
                        "system RAM the ARC is currently using."
                    ),
                    form_spec_template=Float(unit_symbol="%"),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(_DEFAULTS["levels_ram_pct"]),
                ),
            ),
            "levels_hit_ratio": DictElement(
                required=True,
                parameter_form=SimpleLevels[float](
                    title=Title("Levels on ARC hit ratio"),
                    help_text=Help(
                        "Warning/critical levels on the ARC hit ratio in "
                        "percent. Alerts when the ratio drops BELOW the "
                        "given values (a low hit ratio means the cache is "
                        "not effective)."
                    ),
                    form_spec_template=Float(unit_symbol="%"),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue(_DEFAULTS["levels_hit_ratio"]),
                ),
            ),
        },
    )


rule_spec_zfs_arc = CheckParameters(
    title=Title("ZFS ARC cache usage"),
    name="zfs_arc",
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_form_spec_zfs_arc,
    condition=HostCondition(),
)
