#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WATO ruleset for the Commvault REST API special agent."""
from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    MultipleChoice,
    MultipleChoiceElement,
    Password,
    String,
    TimeMagnitude,
    TimeSpan,
    migrate_to_password,
    validators,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("Commvault (via REST API)"),
        help_text=Help(
            "Monitors a Commvault CommServe over its REST API (Command Center API): "
            "the last backup job per subclient, active jobs with their runtime and "
            "wait reason, storage pool status and capacity, and the VM protection "
            "status, the MediaAgent status and the license (expiry and usage). "
            "One piggyback host per protected VM is created. "
            "SQL transaction log jobs are evaluated in the service of their subclient, "
            "separately from the data backups."
        ),
        elements={
            "url": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("API base URL"),
                    help_text=Help(
                        "e.g. https://commserve.example.com/commandcenter/api "
                        "or https://commserve.example.com/webconsole/api (no trailing slash)."
                    ),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "user": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Commvault user"),
                    help_text=Help("A user with view permissions on the CommCell is sufficient."),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "password": DictElement(
                required=True,
                parameter_form=Password(title=Title("Password"), migrate=migrate_to_password),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    label=Label("SSL certificate validation is disabled"),
                    prefill=DefaultValue(False),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Request timeout (seconds)"),
                    help_text=Help("Per request. The job list can take a while on large CommCells."),
                    prefill=DefaultValue(60),
                    custom_validate=(validators.NumberInRange(min_value=5, max_value=600),),
                ),
            ),
            "job_lookback": DictElement(
                required=False,
                parameter_form=TimeSpan(
                    title=Title("Job lookback period"),
                    help_text=Help(
                        "Finished jobs within this period are fetched. A subclient without "
                        "any job in this period goes to the state configured in the job "
                        "check parameters. Should cover the longest backup interval "
                        "(e.g. weekly fulls)."
                    ),
                    displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
                    prefill=DefaultValue(7 * 86400.0),
                    custom_validate=(validators.NumberInRange(min_value=3600.0),),
                ),
            ),
            "page_size": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Jobs per request (page size)"),
                    help_text=Help(
                        "Number of jobs fetched per POST /Jobs request. The CommServe needs "
                        "roughly the same time per request regardless of its size, so the run "
                        "time mainly depends on the number of requests. Lower this only if "
                        "single requests run into the timeout."
                    ),
                    prefill=DefaultValue(5000),
                    custom_validate=(validators.NumberInRange(min_value=100, max_value=10000),),
                ),
            ),
            "sections": DictElement(
                required=False,
                parameter_form=MultipleChoice(
                    title=Title("Data to fetch"),
                    elements=[
                        MultipleChoiceElement(name="jobs", title=Title("Jobs (per subclient and active jobs)")),
                        MultipleChoiceElement(name="storage", title=Title("Storage pools")),
                        MultipleChoiceElement(name="vms", title=Title("Virtual machines (summary)")),
                        MultipleChoiceElement(name="vm_piggyback", title=Title("Piggyback data per VM")),
                        MultipleChoiceElement(name="mediaagents", title=Title("MediaAgent status")),
                        MultipleChoiceElement(name="license", title=Title("License (expiry and usage)")),
                    ],
                    prefill=DefaultValue(["jobs", "storage", "vms", "vm_piggyback", "mediaagents", "license"]),
                ),
            ),
            "skip_ddp": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Ignore 'Distributed Data Platforms' jobs"),
                    label=Label("Create no job services for Distributed Data Platforms (Index Server Backup)"),
                    help_text=Help(
                        "Index Server backups are internal Commvault jobs (agent type 'Distributed Data "
                        "Platforms', usually one subclient per plan). When enabled, these jobs create no "
                        "job services; already discovered services vanish and can be removed by a "
                        "service discovery. The skipped jobs are counted in the service "
                        "'Commvault CommServe'. Active jobs are still shown in 'Commvault active jobs'."
                    ),
                    prefill=DefaultValue(False),
                ),
            ),
        },
    )


rule_spec_commvault_rest = SpecialAgent(
    name="commvault_rest",
    title=Title("Commvault (via REST API)"),
    topic=Topic.APPLICATIONS,
    parameter_form=_formspec,
)
