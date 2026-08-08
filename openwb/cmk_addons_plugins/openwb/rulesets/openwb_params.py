#!/usr/bin/env python3
"""WATO check parameter rulesets for openWB chargepoint/counter/battery checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    SimpleLevels,
    Float,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


# --- Chargepoint power -----------------------------------------------------
def _chargepoint_form():
    return Dictionary(
        elements={
            "power_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Charging power levels"),
                    help_text=Help("Upper levels for the actual chargepoint power."),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="W"),
                    prefill_fixed_levels=DefaultValue((11000.0, 22000.0)),
                ),
            ),
        }
    )


rule_spec_openwb_chargepoint = CheckParameters(
    name="openwb_chargepoint",
    title=Title("openWB chargepoint power"),
    topic=Topic.ENVIRONMENTAL,
    parameter_form=_chargepoint_form,
    condition=HostAndItemCondition(item_title=Title("Chargepoint ID")),
)


# --- Grid counter power -----------------------------------------------------
def _counter_form():
    return Dictionary(
        elements={
            "import_power_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Grid import power levels"),
                    help_text=Help(
                        "Upper levels for the power drawn from the grid "
                        "(positive values = import)."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="W"),
                    prefill_fixed_levels=DefaultValue((5000.0, 8000.0)),
                ),
            ),
        }
    )


rule_spec_openwb_counter = CheckParameters(
    name="openwb_counter",
    title=Title("openWB grid counter power"),
    topic=Topic.ENVIRONMENTAL,
    parameter_form=_counter_form,
    condition=HostAndItemCondition(item_title=Title("Counter ID")),
)


# --- Battery state of charge -------------------------------------------------
def _battery_form():
    return Dictionary(
        elements={
            "soc_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Battery state-of-charge levels"),
                    help_text=Help(
                        "Lower levels for the battery state of charge. "
                        "WARN/CRIT once the SoC drops to or below the "
                        "given percentage."
                    ),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Float(unit_symbol="%"),
                    prefill_fixed_levels=DefaultValue((20.0, 10.0)),
                ),
            ),
        }
    )


rule_spec_openwb_battery = CheckParameters(
    name="openwb_battery",
    title=Title("openWB battery state of charge"),
    topic=Topic.ENVIRONMENTAL,
    parameter_form=_battery_form,
    condition=HostAndItemCondition(item_title=Title("Battery ID")),
)
