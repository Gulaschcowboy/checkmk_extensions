#!/usr/bin/env python3
"""WATO check parameter rulesets for OPNsense service/memory/disk checks."""
from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    ServiceState,
    SimpleLevels,
    Float,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)


# --- Services -------------------------------------------------------------
def _services_form():
    return Dictionary(
        elements={
            "state_not_running": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when an enabled service is not running"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_if_stale": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the service is missing from the API"),
                    prefill=DefaultValue(ServiceState.UNKNOWN),
                ),
            ),
        }
    )


rule_spec_opnsense_services = CheckParameters(
    name="opnsense_services",
    title=Title("OPNsense service state"),
    topic=Topic.NETWORKING,
    parameter_form=_services_form,
    condition=HostAndItemCondition(item_title=Title("Service ID")),
)


# --- Memory ---------------------------------------------------------------
def _pct_levels(title):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            level_direction=LevelDirection.UPPER,
            form_spec_template=Float(unit_symbol="%"),
            prefill_fixed_levels=DefaultValue((80.0, 90.0)),
        ),
    )


def _memory_form():
    return Dictionary(
        elements={"levels": _pct_levels(Title("Memory usage levels"))}
    )


rule_spec_opnsense_memory = CheckParameters(
    name="opnsense_memory",
    title=Title("OPNsense memory usage"),
    topic=Topic.NETWORKING,
    parameter_form=_memory_form,
    condition=HostCondition(),
)


# --- Disk -----------------------------------------------------------------
def _disk_form():
    return Dictionary(
        elements={"levels": _pct_levels(Title("Filesystem usage levels"))}
    )


rule_spec_opnsense_disk = CheckParameters(
    name="opnsense_disk",
    title=Title("OPNsense filesystem usage"),
    topic=Topic.NETWORKING,
    parameter_form=_disk_form,
    condition=HostAndItemCondition(item_title=Title("Mountpoint")),
)
