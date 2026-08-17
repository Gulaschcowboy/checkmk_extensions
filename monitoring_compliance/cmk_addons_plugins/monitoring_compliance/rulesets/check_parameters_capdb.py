#!/usr/bin/env python3
# Check parameters for the "Checkmk Capability Database" service.

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    ServiceState,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _form():
    return Dictionary(
        title=Title("Checkmk Capability Database"),
        help_text=Help(
            "Thresholds for the statistics service of the persistent "
            "capability database."
        ),
        elements={
            "state_if_missing": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the database does not exist yet"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "max_update_age_warn": DictElement(
                parameter_form=TimeSpan(
                    title=Title("WARN if not updated for longer than"),
                    displayed_magnitudes=[
                        TimeMagnitude.DAY,
                        TimeMagnitude.HOUR,
                        TimeMagnitude.MINUTE,
                    ],
                ),
            ),
            "max_update_age_crit": DictElement(
                parameter_form=TimeSpan(
                    title=Title("CRIT if not updated for longer than"),
                    displayed_magnitudes=[
                        TimeMagnitude.DAY,
                        TimeMagnitude.HOUR,
                        TimeMagnitude.MINUTE,
                    ],
                ),
            ),
        },
    )


rule_spec_monitoring_compliance_capdb_params = CheckParameters(
    name="monitoring_compliance_capdb",
    title=Title("Checkmk Capability Database"),
    topic=Topic.GENERAL,
    parameter_form=_form,
    condition=HostCondition(),
)
