#!/usr/bin/env python3
"""WATO ruleset for the Proxmox Backup Server special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("Proxmox Backup Server via REST API"),
        help_text=Help(
            "Poll a Proxmox Backup Server (PBS) over its REST API for node "
            "health, datastore usage, garbage collection and configured "
            "prune / verify / sync / tape jobs. Create an API token under "
            "Configuration > Access Control > API Token. A token with the "
            "'Datastore.Audit' and 'Sys.Audit' privileges (e.g. role "
            "'Audit' on path '/') is sufficient — everything is read-only."
        ),
        elements={
            "token_id": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("API token ID"),
                    help_text=Help("Full token ID, e.g. root@pam!checkmk"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "token_secret": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API token secret"),
                    help_text=Help("The secret shown once when the token was "
                                   "created. May reference the password store."),
                    migrate=migrate_to_password,
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    help_text=Help("TCP port of the PBS API (default 8007)."),
                    prefill=DefaultValue(8007),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "node": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("PBS node name"),
                    help_text=Help("Node name used for node/task endpoints. "
                                   "PBS single-node installs use 'localhost'."),
                    prefill=DefaultValue("localhost"),
                ),
            ),
            "task_limit": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Task history scan depth"),
                    help_text=Help("How many recent tasks to scan when "
                                   "correlating job/GC results."),
                    prefill=DefaultValue(500),
                    custom_validate=(validators.NumberInRange(min_value=10, max_value=5000),),
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    help_text=Help("Enable this if PBS uses a self-signed "
                                   "certificate (default for a fresh install)."),
                    prefill=DefaultValue(True),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Request timeout (seconds)"),
                    prefill=DefaultValue(20),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=300),),
                ),
            ),
        },
    )


rule_spec_pbs = SpecialAgent(
    name="pbs",
    title=Title("Proxmox Backup Server (REST API)"),
    topic=Topic.STORAGE,
    parameter_form=_formspec,
)
