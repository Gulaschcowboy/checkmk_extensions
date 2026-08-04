#!/usr/bin/env python3
"""WATO check parameter rulesets for the Proxmox Backup Server checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    Integer,
    LevelDirection,
    ServiceState,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
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
