#!/usr/bin/env python3
"""WATO check parameter rulesets for the XenServer / XCP-ng checks.

The storage repository capacity check uses the built-in "filesystem" ruleset.
"""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
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
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, HostCondition, Topic

DAYS = [TimeMagnitude.DAY, TimeMagnitude.HOUR]


def _state(title, default, help_text=None):
    return DictElement(
        required=False,
        parameter_form=ServiceState(title=title, help_text=help_text, prefill=DefaultValue(default)),
    )


def _pct_levels(title, prefill=(90.0, 95.0)):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            level_direction=LevelDirection.UPPER,
            form_spec_template=Float(unit_symbol="%"),
            prefill_fixed_levels=DefaultValue(prefill),
        ),
    )


def _time_levels(title, prefill, magnitudes=None, direction=LevelDirection.UPPER, help_text=None):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            help_text=help_text,
            level_direction=direction,
            form_spec_template=TimeSpan(displayed_magnitudes=magnitudes or DAYS),
            prefill_fixed_levels=DefaultValue(prefill),
        ),
    )


def _rule(name, title, elements, item_title=None):
    def form():
        return Dictionary(elements=elements)

    return CheckParameters(
        name=name,
        title=title,
        topic=Topic.VIRTUALIZATION,
        parameter_form=form,
        condition=HostAndItemCondition(item_title=item_title) if item_title else HostCondition(),
    )


rule_spec_xenserver_pool = _rule("xenserver_pool", Title("XenServer pool"), {
    "state_host_disabled": _state(Title("State if a host is disabled (maintenance mode)"), 1),
    "state_rrd_error": _state(Title("State if performance data of a host is not available"), 1),
    "state_failover": _state(Title("State if the configured address is not reachable "
                                   "and a failover address was used"), 1),
    "state_ha_overcommitted": _state(Title("State if HA is overcommitted"), 1),
})

rule_spec_xenserver_alerts = _rule("xenserver_alerts", Title("XenServer alerts"), {
    "prio_1": _state(Title("State for priority 1 (data loss imminent)"), 2),
    "prio_2": _state(Title("State for priority 2 (service loss imminent)"), 2),
    "prio_3": _state(Title("State for priority 3 (service degraded)"), 1),
    "prio_4": _state(Title("State for priority 4 (service recovered)"), 0),
    "ignore": DictElement(
        required=False,
        parameter_form=List(
            title=Title("Ignore alerts"),
            help_text=Help("Regular expressions matched against the alert name "
                           "(e.g. HA_STATEFILE_LOST) and text."),
            element_template=String(),
        ),
    ),
})

rule_spec_xenserver_host = _rule("xenserver_host", Title("XenServer host"), {
    "state_disabled": _state(Title("State if the host is disabled (maintenance mode)"), 1),
    "clock_offset": _time_levels(Title("Clock offset to the Checkmk server"), (30.0, 60.0),
                                 [TimeMagnitude.SECOND]),
})

rule_spec_xenserver_cpu = _rule("xenserver_cpu", Title("XenServer host / VM CPU utilization"), {
    "levels": _pct_levels(Title("Levels on CPU utilization")),
})

rule_spec_xenserver_memory = _rule("xenserver_memory", Title("XenServer host / VM memory usage"), {
    "levels": _pct_levels(Title("Levels on memory usage"),),
})

rule_spec_xenserver_license = _rule("xenserver_license", Title("XenServer license"), {
    "levels": _time_levels(Title("Minimum remaining time until the license expires"),
                           (30 * 86400.0, 14 * 86400.0), direction=LevelDirection.LOWER),
})

rule_spec_xenserver_certificate = _rule("xenserver_certificate", Title("XenServer certificates"), {
    "levels": _time_levels(Title("Minimum remaining time until the certificate expires"),
                           (30 * 86400.0, 14 * 86400.0), direction=LevelDirection.LOWER),
}, item_title=Title("Certificate"))

rule_spec_xenserver_updates = _rule("xenserver_updates", Title("XenServer updates"), {
    "state_not_applied": _state(Title("State if the latest synchronized updates are not applied"), 1),
    "state_guidance": _state(Title("State if a reboot / restart is pending after updates"), 1),
    "sync_age": _time_levels(Title("Maximum age of the last update synchronization"),
                             (8 * 86400.0, 15 * 86400.0)),
})

rule_spec_xenserver_disk_io = _rule("xenserver_disk_io", Title("XenServer SR / VM disk I/O"), {
    "read_latency": _time_levels(Title("Read latency"), (0.02, 0.05),
                                 [TimeMagnitude.MILLISECOND]),
    "write_latency": _time_levels(Title("Write latency"), (0.02, 0.05),
                                  [TimeMagnitude.MILLISECOND]),
}, item_title=Title("Storage repository / disk device"))

rule_spec_xenserver_vm_state = _rule("xenserver_vm_state", Title("XenServer VM state"), {
    "state_running": _state(Title("State if the VM is running"), 0),
    "state_halted": _state(Title("State if the VM is halted"), 0,
                           Help("OK by default: VMs that are shut down on purpose (e.g. "
                                "scheduled stop/start) should not cause alerts. Use a rule "
                                "for VMs that must always run.")),
    "state_paused": _state(Title("State if the VM is paused"), 1),
    "state_suspended": _state(Title("State if the VM is suspended"), 0),
    "state_requires_reboot": _state(Title("State if the VM requires a reboot"), 0),
})

rule_spec_xenserver_snapshots = _rule("xenserver_snapshots", Title("XenServer VM snapshots"), {
    "age_oldest": _time_levels(Title("Maximum age of the oldest snapshot"),
                               (7 * 86400.0, 30 * 86400.0)),
    "count": DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=Title("Maximum number of snapshots"),
            level_direction=LevelDirection.UPPER,
            form_spec_template=Integer(),
            prefill_fixed_levels=DefaultValue((5, 10)),
        ),
    ),
})

rule_spec_xenserver_guest_tools = _rule("xenserver_guest_tools", Title("XenServer VM guest tools"), {
    "state_missing": _state(Title("State if no guest tools report on a running VM"), 1),
    "state_outdated": _state(Title("State if the PV drivers are out of date"), 0),
})
