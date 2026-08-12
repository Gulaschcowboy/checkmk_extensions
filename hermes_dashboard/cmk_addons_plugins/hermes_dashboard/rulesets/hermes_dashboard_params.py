#!/usr/bin/env python3
"""WATO check parameter rulesets for the Hermes Agent dashboard checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    LevelDirection,
    ServiceState,
    SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)


# --- Overview ----------------------------------------------------------
def _overview_form():
    return Dictionary(
        elements={
            "state_update_available": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when a Hermes update is available"),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
        }
    )


rule_spec_hermes_dashboard_overview = CheckParameters(
    name="hermes_dashboard_overview",
    title=Title("Hermes dashboard overview"),
    topic=Topic.APPLICATIONS,
    parameter_form=_overview_form,
    condition=HostCondition(),
)


# --- Gateway -------------------------------------------------------------
def _gateway_form():
    return Dictionary(
        elements={
            "state_stopped": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the gateway is stopped"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        }
    )


rule_spec_hermes_dashboard_gateway = CheckParameters(
    name="hermes_dashboard_gateway",
    title=Title("Hermes gateway process state"),
    topic=Topic.APPLICATIONS,
    parameter_form=_gateway_form,
    condition=HostCondition(),
)


# --- Platform --------------------------------------------------------------
def _platform_form():
    return Dictionary(
        elements={
            "state_disconnected": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the platform is disconnected"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        }
    )


rule_spec_hermes_dashboard_platform = CheckParameters(
    name="hermes_dashboard_platform",
    title=Title("Hermes gateway platform connection"),
    topic=Topic.APPLICATIONS,
    parameter_form=_platform_form,
    condition=HostAndItemCondition(item_title=Title("Platform")),
)


# --- Component -------------------------------------------------------------
def _component_form():
    return Dictionary(
        elements={
            "state_recent_errors": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when recent unhandled errors > 0"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_platform_gap": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when fewer platforms are connected than configured"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        }
    )


rule_spec_hermes_dashboard_component = CheckParameters(
    name="hermes_dashboard_component",
    title=Title("Hermes dashboard component health"),
    topic=Topic.APPLICATIONS,
    parameter_form=_component_form,
    condition=HostAndItemCondition(item_title=Title("Component")),
)


# --- Usage / cost ------------------------------------------------------
def _usage_form():
    return Dictionary(
        elements={
            "cost_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Levels on estimated usage cost (USD)"),
                    help_text=Help(
                        "Warn/crit thresholds on the estimated USD cost "
                        "over the configured reporting window (see the "
                        "special agent's 'Usage reporting window' option, "
                        "default 1 day)."
                    ),
                    form_spec_template=Float(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((10.0, 25.0)),
                ),
            ),
        }
    )


rule_spec_hermes_dashboard_usage = CheckParameters(
    name="hermes_dashboard_usage",
    title=Title("Hermes dashboard token/cost usage"),
    topic=Topic.APPLICATIONS,
    parameter_form=_usage_form,
    condition=HostCondition(),
)
