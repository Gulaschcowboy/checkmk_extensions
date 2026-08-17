#!/usr/bin/env python3
# Check parameters for the "Checkmk Monitoring Compliance" service.

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    List,
    ServiceState,
    String,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic


def _custom_rule() -> Dictionary:
    return Dictionary(
        elements={
            "pattern": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Capability name regex"),
                    help_text=Help(
                        "Matched against a capability's raw name (process, "
                        "package, unit or label value)."),
                ),
            ),
            "token": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Maps to plug-in token"),
                    help_text=Help(
                        "Leading token of the Checkmk plug-in that monitors it, "
                        "e.g. 'mysql' for mysql_status, 'postgres' for "
                        "postgres_sessions."),
                ),
            ),
            "title": DictElement(
                parameter_form=String(title=Title("Display name")),
            ),
            "enable_hint": DictElement(
                parameter_form=String(title=Title("Hint how to enable")),
            ),
        },
    )


def _form():
    return Dictionary(
        title=Title("Checkmk Monitoring Compliance"),
        help_text=Help(
            "Controls how the compliance service evaluates detected "
            "capabilities that are not yet monitored."
        ),
        elements={
            "state_running_unmonitored": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when: running, not monitored"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_installed_unmonitored": DictElement(
                parameter_form=ServiceState(
                    title=Title("State when: present, not running, not monitored"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "informational_only": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Informational only"),
                    label=Label("Never set the service to WARN/CRIT"),
                ),
            ),
            "ignored_processes": DictElement(
                parameter_form=List(
                    title=Title(
                        "Ignore processes / systemd units / services (regex)"),
                    help_text=Help(
                        "Regex matched against running-type capability names: "
                        "processes, systemd units and Windows services. A "
                        "match removes that detection. The service long output "
                        "shows where each subsystem was detected, to help you "
                        "write these patterns."),
                    element_template=String(),
                ),
            ),
            "ignored_programs": DictElement(
                parameter_form=List(
                    title=Title("Ignore installed programs (regex)"),
                    help_text=Help(
                        "Regex matched against installed-package capability "
                        "names (package lists and HW/SW inventory packages)."),
                    element_template=String(),
                ),
            ),
            "custom_catalog": DictElement(
                parameter_form=List(
                    title=Title("Custom capability mappings"),
                    help_text=Help(
                        "Extend detection with your own name-to-plug-in "
                        "mappings."),
                    element_template=_custom_rule(),
                ),
            ),
            "disable_capability_db": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Do not write the capability database"),
                    label=Label("Disable the persistent capability database"),
                ),
            ),
            "capability_db_path": DictElement(
                parameter_form=String(
                    title=Title("Alternative capability database path"),
                    help_text=Help(
                        "Default: $OMD_ROOT/var/monitoring_compliance/"
                        "capability_db.json"),
                ),
            ),
        },
    )


rule_spec_monitoring_compliance_params = CheckParameters(
    name="monitoring_compliance",
    title=Title("Checkmk Monitoring Compliance"),
    topic=Topic.GENERAL,
    parameter_form=_form,
    condition=HostCondition(),
)
