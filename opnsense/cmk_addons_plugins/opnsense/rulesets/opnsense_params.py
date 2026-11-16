#!/usr/bin/env python3
"""WATO check parameter rulesets for OPNsense service/memory/disk checks."""
from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    ServiceState,
    SimpleLevels,
    Float,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostAndItemCondition,
    HostCondition,
    Topic,
)


# --- Services -------------------------------------------------------------
def _services_form():
    return Dictionary(
        elements={
            "state_not_running": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when an enabled service is not running"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_if_stale": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the service is missing from the API"),
                    prefill=DefaultValue(ServiceState.UNKNOWN),
                ),
            ),
        }
    )


rule_spec_opnsense_services = CheckParameters(
    name="opnsense_services",
    title=Title("OPNsense service state"),
    topic=Topic.NETWORKING,
    parameter_form=_services_form,
    condition=HostAndItemCondition(item_title=Title("Service ID")),
)


# --- Memory ---------------------------------------------------------------
def _pct_levels(title):
    return DictElement(
        required=False,
        parameter_form=SimpleLevels(
            title=title,
            level_direction=LevelDirection.UPPER,
            form_spec_template=Float(unit_symbol="%"),
            prefill_fixed_levels=DefaultValue((80.0, 90.0)),
        ),
    )


def _memory_form():
    return Dictionary(
        elements={"levels": _pct_levels(Title("Memory usage levels"))}
    )


rule_spec_opnsense_memory = CheckParameters(
    name="opnsense_memory",
    title=Title("OPNsense memory usage"),
    topic=Topic.NETWORKING,
    parameter_form=_memory_form,
    condition=HostCondition(),
)


# --- Disk -----------------------------------------------------------------
def _disk_form():
    return Dictionary(
        elements={"levels": _pct_levels(Title("Filesystem usage levels"))}
    )


rule_spec_opnsense_disk = CheckParameters(
    name="opnsense_disk",
    title=Title("OPNsense filesystem usage"),
    topic=Topic.NETWORKING,
    parameter_form=_disk_form,
    condition=HostAndItemCondition(item_title=Title("Mountpoint")),
)


# --- SMART disk health ------------------------------------------------------
def _smart_form():
    return Dictionary(
        elements={
            "state_when_failed": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when SMART health is FAILED"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "levels_temperature": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Disk temperature levels"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="°C"),
                    prefill_fixed_levels=DefaultValue((45.0, 55.0)),
                ),
            ),
            "levels_ssd_life": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("SSD life remaining levels"),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Float(unit_symbol="%"),
                    prefill_fixed_levels=DefaultValue((50.0, 25.0)),
                ),
            ),
        }
    )


rule_spec_opnsense_smart = CheckParameters(
    name="opnsense_smart",
    title=Title("OPNsense disk health (SMART)"),
    topic=Topic.NETWORKING,
    parameter_form=_smart_form,
    condition=HostAndItemCondition(item_title=Title("Disk device")),
)


def _state(title, default):
    return DictElement(
        required=False,
        parameter_form=ServiceState(title=Title(title), prefill=DefaultValue(default)),
    )


# --- Gateways -------------------------------------------------------------
def _gateways_form():
    return Dictionary(
        elements={
            "state_loss": _state("State when dpinger reports packet loss", ServiceState.WARN),
            "state_delay": _state("State when dpinger reports high latency", ServiceState.WARN),
            "state_delay_loss": _state("State on high latency and packet loss", ServiceState.WARN),
            "state_down": _state("State when the gateway is offline", ServiceState.CRIT),
            "state_force_down": _state("State when the gateway is forced down", ServiceState.WARN),
            "state_missing": _state("State when the gateway is missing", ServiceState.UNKNOWN),
            "levels_rtt": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Round trip time"),
                    help_text=Help("Own levels in addition to the dpinger status "
                                   "configured on the gateway in OPNsense."),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="ms"),
                    prefill_fixed_levels=DefaultValue((100.0, 250.0)),
                ),
            ),
            "levels_loss": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Packet loss"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="%"),
                    prefill_fixed_levels=DefaultValue((10.0, 20.0)),
                ),
            ),
        }
    )


rule_spec_opnsense_gateways = CheckParameters(
    name="opnsense_gateways",
    title=Title("OPNsense gateways"),
    topic=Topic.NETWORKING,
    parameter_form=_gateways_form,
    condition=HostAndItemCondition(item_title=Title("Gateway name")),
)


# --- WireGuard ------------------------------------------------------------
def _wireguard_form():
    return Dictionary(
        elements={
            "levels_handshake_age": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum age of the latest handshake"),
                    help_text=Help("WireGuard renews the handshake about every "
                                   "2 minutes while traffic flows. Peers without "
                                   "traffic (no keepalive) may legitimately be "
                                   "idle - disable the levels for those."),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.HOUR,
                                              TimeMagnitude.MINUTE,
                                              TimeMagnitude.SECOND]),
                    prefill_fixed_levels=DefaultValue((300.0, 900.0)),
                ),
            ),
            "state_no_handshake": _state("State when no handshake happened yet", ServiceState.WARN),
            "state_missing": _state("State when the peer is missing", ServiceState.UNKNOWN),
        }
    )


rule_spec_opnsense_wireguard = CheckParameters(
    name="opnsense_wireguard",
    title=Title("OPNsense WireGuard peers"),
    topic=Topic.NETWORKING,
    parameter_form=_wireguard_form,
    condition=HostAndItemCondition(item_title=Title("Interface and peer name")),
)


# --- DHCP pools -----------------------------------------------------------
def _dhcp_form():
    return Dictionary(
        elements={
            "levels_used": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Pool usage"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="%"),
                    prefill_fixed_levels=DefaultValue((80.0, 90.0)),
                ),
            ),
        }
    )


rule_spec_opnsense_dhcp = CheckParameters(
    name="opnsense_dhcp",
    title=Title("OPNsense DHCP pool usage"),
    topic=Topic.NETWORKING,
    parameter_form=_dhcp_form,
    condition=HostAndItemCondition(item_title=Title("DHCP pool")),
)


# --- Temperature ----------------------------------------------------------
def _temperature_form():
    return Dictionary(
        elements={
            "levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Temperature levels"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="°C"),
                    prefill_fixed_levels=DefaultValue((70.0, 80.0)),
                ),
            ),
        }
    )


rule_spec_opnsense_temperature = CheckParameters(
    name="opnsense_temperature",
    title=Title("OPNsense temperature sensors"),
    topic=Topic.NETWORKING,
    parameter_form=_temperature_form,
    condition=HostAndItemCondition(item_title=Title("Sensor")),
)


# --- Package audit --------------------------------------------------------
def _audit_form():
    return Dictionary(
        elements={
            "state_vulnerable": _state("State when vulnerable packages are found", ServiceState.WARN),
            "state_audit_error": _state("State when the audit itself fails", ServiceState.WARN),
            "levels_age": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Maximum age of the audit result"),
                    help_text=Help("Default: 2 / 4 audit intervals plus one hour."),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY,
                                              TimeMagnitude.HOUR,
                                              TimeMagnitude.MINUTE]),
                    prefill_fixed_levels=DefaultValue((86400.0, 172800.0)),
                ),
            ),
        }
    )


rule_spec_opnsense_audit = CheckParameters(
    name="opnsense_audit",
    title=Title("OPNsense package audit"),
    topic=Topic.NETWORKING,
    parameter_form=_audit_form,
    condition=HostCondition(),
)
