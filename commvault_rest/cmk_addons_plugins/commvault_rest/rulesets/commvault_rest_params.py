#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WATO check parameter rulesets for the Commvault REST checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    InputHint,
    LevelDirection,
    List,
    Percentage,
    LevelsType,
    ServiceState,
    SimpleLevels,
    String,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.form_specs.validators import LengthInRange
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, HostCondition, Topic

_MAGNITUDES = [TimeMagnitude.DAY, TimeMagnitude.HOUR, TimeMagnitude.MINUTE]


def _state(title: str, default, help_text: str | None = None) -> DictElement:
    return DictElement(
        required=False,
        parameter_form=ServiceState(
            title=Title(title),  # pylint: disable=localization-checker
            help_text=Help(help_text) if help_text else None,  # pylint: disable=localization-checker
            prefill=DefaultValue(default),
        ),
    )


def _age_levels(title: str, help_text: str) -> DictElement:
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=Title(title),  # pylint: disable=localization-checker
            help_text=Help(help_text),  # pylint: disable=localization-checker
            level_direction=LevelDirection.UPPER,
            form_spec_template=TimeSpan(displayed_magnitudes=_MAGNITUDES),
            prefill_fixed_levels=InputHint((26 * 3600.0, 50 * 3600.0)),
            prefill_levels_type=DefaultValue(LevelsType.NONE),
        ),
    )


def _job_form():
    return Dictionary(
        elements={
            "state_completed": _state("State for 'Completed'", ServiceState.OK),
            "state_completed_warnings": _state("State for 'Completed w/ one or more warnings'", ServiceState.WARN),
            "state_completed_errors": _state("State for 'Completed w/ one or more errors'", ServiceState.WARN),
            "state_committed": _state("State for 'Committed'", ServiceState.WARN,
                                      "A job that was stopped and whose already transferred data was kept."),
            "state_failed": _state("State for 'Failed'", ServiceState.CRIT),
            "state_killed": _state("State for 'Killed'", ServiceState.CRIT),
            "state_other": _state("State for any other job status", ServiceState.WARN),
            "state_no_job": _state("State if no job ran within the lookback period", ServiceState.WARN,
                                   "Only applies while the service still exists; the lookback period is "
                                   "set in the special agent rule."),
            "state_no_success": _state("State if no job within the lookback period was successful",
                                       ServiceState.WARN),
            "max_age_success": _age_levels(
                "Maximum age of the last successful job",
                "Only jobs within the lookback period of the special agent are known; "
                "older successful jobs are reported as 'no successful job'. "
                "SQL transaction log jobs are not counted here, see the next option.",
            ),
            "max_age_log_success": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum age of the last successful SQL transaction log job"),
                    help_text=Help(
                        "Only for subclients with SQL transaction log backups. The log jobs are "
                        "evaluated separately from the data backups (full, incremental, differential) "
                        "in the same service: state of the last log job and age of the last successful "
                        "one. The job states above apply to both. Default: 6 h / 12 h."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(displayed_magnitudes=_MAGNITUDES),
                    prefill_fixed_levels=DefaultValue((6 * 3600.0, 12 * 3600.0)),
                ),
            ),
        }
    )


rule_spec_commvault_rest_job = CheckParameters(
    name="commvault_rest_job",
    title=Title("Commvault jobs per subclient"),
    topic=Topic.APPLICATIONS,
    parameter_form=_job_form,
    condition=HostAndItemCondition(item_title=Title("Subclient")),
)


def _active_jobs_form():
    return Dictionary(
        elements={
            "max_runtime": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum runtime of an active job"),
                    help_text=Help(
                        "Applies to every running or waiting job whose job type has no entry in "
                        "'Maximum runtime per job type'. Default: 24 h / 72 h."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(displayed_magnitudes=_MAGNITUDES),
                    prefill_fixed_levels=DefaultValue((24 * 3600.0, 72 * 3600.0)),
                ),
            ),
            "max_runtime_per_type": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Maximum runtime per job type"),
                    help_text=Help(
                        "Own runtime levels for specific job types. The job type is compared with the "
                        "type reported by the Commvault API (case-insensitive, exact name), the first "
                        "matching entry wins. Jobs of other types use 'Maximum runtime of an active job'. "
                        "The API names can differ from the documentation (e.g. 'Aux Copy' instead of "
                        "'Auxiliary Copy'); the service details show the type of every active job. "
                        "Examples: Backup, Restore, Aux Copy, DDB Verification, DDB Space Reclamation, "
                        "Index Server Backup, Synthetic Full, Archive, Data Aging. "
                        "Choose 'No levels' to skip the runtime check for a job type."
                    ),
                    element_template=Dictionary(
                        elements={
                            "job_types": DictElement(
                                required=True,
                                parameter_form=List(
                                    title=Title("Job types"),
                                    element_template=String(
                                        title=Title("Job type"),
                                        custom_validate=(LengthInRange(min_value=1),),
                                    ),
                                    custom_validate=(LengthInRange(min_value=1),),
                                ),
                            ),
                            "max_runtime": DictElement(
                                required=True,
                                parameter_form=SimpleLevels(
                                    title=Title("Maximum runtime"),
                                    level_direction=LevelDirection.UPPER,
                                    form_spec_template=TimeSpan(displayed_magnitudes=_MAGNITUDES),
                                    prefill_fixed_levels=DefaultValue((24 * 3600.0, 72 * 3600.0)),
                                ),
                            ),
                        }
                    ),
                ),
            ),
        }
    )


rule_spec_commvault_rest_active_jobs = CheckParameters(
    name="commvault_rest_active_jobs",
    title=Title("Commvault active jobs"),
    topic=Topic.APPLICATIONS,
    parameter_form=_active_jobs_form,
    condition=HostCondition(),
)


def _vms_form():
    return Dictionary(
        elements={
            "state_missed_sla": _state("State if VMs missed their SLA", ServiceState.WARN),
            "state_failed": _state("State if VMs have status FAILED", ServiceState.WARN),
            "state_warning": _state("State if VMs have status WARNING", ServiceState.OK),
        }
    )


rule_spec_commvault_rest_vms = CheckParameters(
    name="commvault_rest_vms",
    title=Title("Commvault VM summary"),
    topic=Topic.APPLICATIONS,
    parameter_form=_vms_form,
    condition=HostCondition(),
)


def _vm_form():
    return Dictionary(
        elements={
            "state_sla_met": _state("State if the SLA is met", ServiceState.OK),
            "state_sla_missed": _state("State if the SLA is missed", ServiceState.CRIT),
            "state_sla_excluded": _state("State if the VM is excluded from the SLA", ServiceState.OK,
                                         "Excluded VMs (e.g. 'Backup activity disabled') are not "
                                         "evaluated further."),
            "state_protected": _state("State for VM status PROTECTED", ServiceState.OK),
            "state_warning": _state("State for VM status WARNING", ServiceState.WARN),
            "state_failed": _state("State for VM status FAILED", ServiceState.CRIT),
            "state_not_protected": _state("State for VM status NOT_PROTECTED", ServiceState.WARN),
            "state_discovered": _state("State for VM status DISCOVERED", ServiceState.WARN),
            "state_other": _state("State for any other SLA or VM status", ServiceState.WARN),
            "max_age_success": _age_levels(
                "Maximum age of the last successful backup",
                "Not applied to VMs that are excluded from the SLA.",
            ),
        }
    )


rule_spec_commvault_rest_vm = CheckParameters(
    name="commvault_rest_vm",
    title=Title("Commvault VM backup"),
    topic=Topic.APPLICATIONS,
    parameter_form=_vm_form,
    condition=HostCondition(),
)


def _mediaagent_form():
    return Dictionary(
        elements={
            "state_offline": _state("State if the MediaAgent is offline", ServiceState.CRIT,
                                    "E.g. 'Cannot communicate with Media Mount Manager Service' or "
                                    "a version mismatch with the CommServe."),
            "state_offline_no_error": _state("State if offline with reason 'No errors detected'",
                                             ServiceState.WARN,
                                             "Offline reason code 0: the CommServe marks the MediaAgent "
                                             "offline without reporting an error."),
            "state_unlicensed": _state("State for an unlicensed MediaAgent", ServiceState.WARN),
            "state_other": _state("State for any other status", ServiceState.WARN),
        }
    )


rule_spec_commvault_rest_mediaagent = CheckParameters(
    name="commvault_rest_mediaagent",
    title=Title("Commvault MediaAgents"),
    topic=Topic.APPLICATIONS,
    parameter_form=_mediaagent_form,
    condition=HostAndItemCondition(item_title=Title("MediaAgent")),
)


def _license_form():
    return Dictionary(
        elements={
            "expiry_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Minimum remaining time until the license expires"),
                    help_text=Help("Default: warning below 60 days, critical below 30 days."),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=TimeSpan(displayed_magnitudes=[TimeMagnitude.DAY]),
                    prefill_fixed_levels=DefaultValue((60 * 86400.0, 30 * 86400.0)),
                ),
            ),
            "state_not_production": _state("State if the license mode is not PRODUCTION", ServiceState.WARN),
            "state_no_expiry": _state("State if no expiry date is reported", ServiceState.WARN),
            "state_over_capacity_msg": _state("State if the CommServe reports over capacity", ServiceState.WARN),
            "state_grace_period": _state("State if a grace period is active", ServiceState.WARN),
        }
    )


rule_spec_commvault_rest_license = CheckParameters(
    name="commvault_rest_license",
    title=Title("Commvault license"),
    topic=Topic.APPLICATIONS,
    parameter_form=_license_form,
    condition=HostCondition(),
)


def _license_usage_form():
    return Dictionary(
        elements={
            "usage_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum license usage"),
                    help_text=Help("Used amount in percent of the licensed amount. Default: 90 % / 95 %."),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Percentage(),
                    prefill_fixed_levels=DefaultValue((90.0, 95.0)),
                ),
            ),
            "state_expired": _state("State if the license type is flagged as expired", ServiceState.CRIT),
        }
    )


rule_spec_commvault_rest_license_usage = CheckParameters(
    name="commvault_rest_license_usage",
    title=Title("Commvault license usage"),
    topic=Topic.APPLICATIONS,
    parameter_form=_license_usage_form,
    condition=HostAndItemCondition(item_title=Title("License type")),
)
