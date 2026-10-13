#!/usr/bin/env python3
"""Rulesets for the per-tunnel FortiGate IPsec VPN check."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    Dictionary,
    DictElement,
    ServiceState,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    DiscoveryParameters,
    HostAndItemCondition,
    Topic,
)


def _parameter_form_check() -> Dictionary:
    return Dictionary(
        title=Title("FortiGate IPsec VPN tunnel"),
        help_text=Help(
            "State of a single FortiGate IPsec VPN tunnel (phase 2 selector). "
            "To accept a specific tunnel being down, e.g. an on-demand tunnel, "
            "create a rule restricted to that tunnel and set the state to OK."
        ),
        elements={
            "state_down": DictElement(
                required=True,
                parameter_form=ServiceState(
                    title=Title("State if the tunnel is down"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        },
    )


rule_spec_fortigate_vpn_tunnel = CheckParameters(
    name="fortigate_vpn_tunnel",
    title=Title("FortiGate IPsec VPN tunnel (per tunnel)"),
    topic=Topic.NETWORKING,
    parameter_form=_parameter_form_check,
    condition=HostAndItemCondition(item_title=Title("Phase 2 name")),
)


def _parameter_form_discovery() -> Dictionary:
    return Dictionary(
        title=Title("FortiGate IPsec VPN tunnel discovery"),
        elements={
            "discover_down": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Tunnels that are down"),
                    label=Label("Also create services for tunnels that are down during discovery"),
                    help_text=Help(
                        "By default every configured phase 2 selector gets a service. "
                        "Uncheck this to only create services for tunnels that are up "
                        "at discovery time."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
        },
    )


rule_spec_discovery_fortigate_vpn_tunnel = DiscoveryParameters(
    name="discovery_fortigate_vpn_tunnel",
    title=Title("FortiGate IPsec VPN tunnel discovery"),
    topic=Topic.NETWORKING,
    parameter_form=_parameter_form_discovery,
)
