#!/usr/bin/env python3
"""WATO check parameter rulesets for the Proxmox Backup Server checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    Float,
    Integer,
    LevelDirection,
    List,
    ServiceState,
    SimpleLevels,
    String,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    DiscoveryParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)


def _pct_levels(title, prefill=(80.0, 90.0)):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            level_direction=LevelDirection.UPPER,
            form_spec_template=Float(unit_symbol="%"),
            prefill_fixed_levels=DefaultValue(prefill),
        ),
    )


def _age_levels(title, prefill=(90000.0, 172800.0)):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            level_direction=LevelDirection.UPPER,
            form_spec_template=TimeSpan(
                displayed_magnitudes=[
                    TimeMagnitude.DAY,
                    TimeMagnitude.HOUR,
                    TimeMagnitude.MINUTE,
                ],
            ),
            prefill_fixed_levels=DefaultValue(prefill),
        ),
    )


# --- Node ------------------------------------------------------------------
def _node_form():
    return Dictionary(
        elements={
            "cpu_levels": _pct_levels(Title("CPU utilization levels")),
        }
    )


rule_spec_proxmox_backup_server_api_node = CheckParameters(
    name="proxmox_backup_server_api_node",
    title=Title("PBS node CPU / load"),
    topic=Topic.STORAGE,
    parameter_form=_node_form,
    condition=HostCondition(),
)


# --- Node memory -----------------------------------------------------------
def _memory_form():
    return Dictionary(elements={"levels": _pct_levels(Title("RAM usage levels"))})


rule_spec_proxmox_backup_server_api_memory = CheckParameters(
    name="proxmox_backup_server_api_memory",
    title=Title("PBS node memory usage"),
    topic=Topic.STORAGE,
    parameter_form=_memory_form,
    condition=HostCondition(),
)


# --- Node root fs ----------------------------------------------------------
def _rootfs_form():
    return Dictionary(elements={"levels": _pct_levels(Title("Root filesystem usage levels"))})


rule_spec_proxmox_backup_server_api_rootfs = CheckParameters(
    name="proxmox_backup_server_api_rootfs",
    title=Title("PBS node root filesystem usage"),
    topic=Topic.STORAGE,
    parameter_form=_rootfs_form,
    condition=HostCondition(),
)


# --- Subscription ----------------------------------------------------------
def _subscription_form():
    return Dictionary(
        elements={
            "state_notfound": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when no subscription key is present"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        }
    )


rule_spec_proxmox_backup_server_api_subscription = CheckParameters(
    name="proxmox_backup_server_api_subscription",
    title=Title("PBS subscription status"),
    topic=Topic.STORAGE,
    parameter_form=_subscription_form,
    condition=HostCondition(),
)


# --- Datastore -------------------------------------------------------------
def _datastore_form():
    return Dictionary(
        elements={
            "levels": _pct_levels(Title("Datastore usage levels")),
            "full_horizon_days": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Alert when estimated-full is within N days"),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Integer(unit_symbol="days"),
                    prefill_fixed_levels=DefaultValue((30, 7)),
                ),
            ),
        }
    )


rule_spec_proxmox_backup_server_api_datastore = CheckParameters(
    name="proxmox_backup_server_api_datastore",
    title=Title("PBS datastore usage"),
    topic=Topic.STORAGE,
    parameter_form=_datastore_form,
    condition=HostAndItemCondition(item_title=Title("Datastore")),
)


# --- Garbage collection ----------------------------------------------------
def _gc_form():
    return Dictionary(
        elements={
            "state_failed": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when last GC failed"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_warn": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when last GC finished with warnings"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_never_run": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when GC has never run"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "max_age": _age_levels(Title("Maximum age since last successful GC")),
        }
    )


rule_spec_proxmox_backup_server_api_gc = CheckParameters(
    name="proxmox_backup_server_api_gc",
    title=Title("PBS garbage collection"),
    topic=Topic.STORAGE,
    parameter_form=_gc_form,
    condition=HostAndItemCondition(item_title=Title("Datastore")),
)


# --- Jobs (prune/verify/sync/tape) ----------------------------------------
def _jobs_form():
    return Dictionary(
        elements={
            "state_failed": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the last job run failed"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_warn": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the last job run had warnings"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_never_run": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the job has never run"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_disabled": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the job is disabled"),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
            "max_age": _age_levels(Title("Maximum age since last successful run")),
        }
    )


rule_spec_proxmox_backup_server_api_jobs = CheckParameters(
    name="proxmox_backup_server_api_jobs",
    title=Title("PBS backup jobs (prune/verify/sync/tape)"),
    topic=Topic.STORAGE,
    parameter_form=_jobs_form,
    condition=HostAndItemCondition(item_title=Title("Job")),
)


# --- Snapshot age (backup freshness) --------------------------------------
def _snapshots_form():
    return Dictionary(
        elements={
            "err_days": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum age of the newest backup per group"),
                    help_text=Help(
                        "Warn/crit when the newest backup of a VM/CT/host is "
                        "older than the configured age."
                    ),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                            TimeMagnitude.MINUTE,
                        ],
                    ),
                    prefill_fixed_levels=DefaultValue((2 * 86400.0, 10 * 86400.0)),
                ),
            ),
            "throw_warnings": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Actually raise WARN/CRIT states"),
                    help_text=Help(
                        "When disabled, stale backups are reported in the "
                        "summary but the service stays OK."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
            "ignore_old_errors": DictElement(
                required=False,
                parameter_form=TimeSpan(
                    title=Title("Ignore backups older than"),
                    help_text=Help(
                        "Backups older than this are treated as abandoned and "
                        "no longer counted towards WARN/CRIT (they are still "
                        "listed in the details)."
                    ),
                    displayed_magnitudes=[
                        TimeMagnitude.DAY,
                        TimeMagnitude.HOUR,
                    ],
                ),
            ),
            "ignore_groups": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("Ignore these groups"),
                    help_text=Help(
                        "Backup groups listed here are completely excluded "
                        "from this check — they are neither counted nor shown "
                        "in the details. Enter one group per line in the "
                        "'<type>/<id>' notation, e.g. 'vm/9000', "
                        "'ct/300' or 'host/pve0'. Shell-style wildcards are "
                        "supported, so 'vm/*' ignores every VM and '*/9000' "
                        "ignores id 9000 of any type."
                    ),
                    element_template=String(
                        prefill=DefaultValue("vm/9000"),
                    ),
                ),
            ),
        }
    )


rule_spec_proxmox_backup_server_api_snapshots = CheckParameters(
    name="proxmox_backup_server_api_snapshots",
    title=Title("PBS backup age (freshness)"),
    topic=Topic.STORAGE,
    parameter_form=_snapshots_form,
    condition=HostAndItemCondition(item_title=Title("Datastore / namespace")),
)


# --- Snapshot age discovery -----------------------------------------------
def _snapshots_discovery_form():
    return Dictionary(
        elements={
            "datastores": DictElement(
                required=True,
                parameter_form=CascadingSingleChoice(
                    title=Title("Discover backup-age services for datastores"),
                    prefill=DefaultValue("all"),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="all",
                            title=Title("All datastores"),
                            parameter_form=FixedValue(value="all"),
                        ),
                        CascadingSingleChoiceElement(
                            name="regex",
                            title=Title("Datastores matching a regular expression"),
                            parameter_form=String(
                                prefill=DefaultValue(".*"),
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="selected",
                            title=Title("Explicitly selected datastores"),
                            parameter_form=String(
                                help_text=Help(
                                    "One datastore name per line."
                                ),
                            ),
                        ),
                    ],
                ),
            ),
        }
    )


rule_spec_proxmox_backup_server_api_snapshots_discovery = DiscoveryParameters(
    name="proxmox_backup_server_api_snapshots_discovery",
    title=Title("PBS backup age discovery"),
    topic=Topic.STORAGE,
    parameter_form=_snapshots_discovery_form,
)
