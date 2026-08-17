#!/usr/bin/env python3
# Rule to enable the server-side compliance data source per host.
# Setup > Agents > Other integrations.

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    String,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _form():
    return Dictionary(
        title=Title("Checkmk Monitoring Compliance"),
        help_text=Help(
            "Enables the server-side data source that determines which check "
            "plug-ins are active on the host (Livestatus), which plug-ins the "
            "site knows ('cmk -L'), the host labels, and the installed packages "
            "from the HW/SW inventory. Set the host's 'Checkmk agent / API "
            "integrations' option to 'Configured API integrations and Checkmk "
            "agent' so this runs alongside the regular agent."
        ),
        elements={
            "cache_ttl": DictElement(
                parameter_form=Integer(
                    title=Title("Cache duration of the plug-in list (seconds)"),
                    prefill=DefaultValue(3600),
                ),
            ),
            "no_plugin_check": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Do not check plug-in availability ('cmk -L')"),
                ),
            ),
            "no_labels": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Do not collect host labels"),
                ),
            ),
            "no_inventory": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Do not read HW/SW inventory packages"),
                ),
            ),
            "report_db_stats": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Report capability database statistics"),
                    help_text=Help(
                        "Emit a statistics section for the persistent "
                        "capability database, which creates the additional "
                        "'Checkmk Capability Database' service. Enable this on "
                        "exactly one host (e.g. the Checkmk server host)."
                    ),
                ),
            ),
            "db_path": DictElement(
                parameter_form=String(
                    title=Title("Alternative capability database path"),
                    help_text=Help(
                        "Must match the path configured in the check "
                        "parameters. Default: $OMD_ROOT/var/"
                        "monitoring_compliance/capability_db.json"),
                ),
            ),
            "report_known_catalog": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Report known catalog"),
                    help_text=Help(
                        "Emit the read-only known-catalog section, which "
                        "creates the informational 'Checkmk Known Catalog' "
                        "service listing all application types the detection "
                        "knows about. Enable on one host."
                    ),
                ),
            ),
            "livestatus_socket": DictElement(
                parameter_form=String(
                    title=Title("Alternative Livestatus socket path"),
                    help_text=Help("Default: $OMD_ROOT/tmp/run/live."),
                ),
            ),
        },
    )


rule_spec_monitoring_compliance_agent = SpecialAgent(
    name="monitoring_compliance",
    title=Title("Checkmk Monitoring Compliance"),
    topic=Topic.GENERAL,
    parameter_form=_form,
)
