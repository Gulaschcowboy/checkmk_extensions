#!/usr/bin/env python3
"""WATO ruleset for the OPNsense special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    Password,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.form_specs import BooleanChoice
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _formspec():
    return Dictionary(
        title=Title("OPNsense via REST API"),
        help_text=Help(
            "Poll an OPNsense firewall over its REST API for firmware "
            "update status, running services, system diagnostics and, "
            "when the os-smart plugin is installed, SMART disk health. "
            "Create an API key/secret under System > Access > Users > "
            "[user] > API keys. A dedicated user with the privileges "
            "'System: Firmware', 'System: Status', 'Status: Services' and "
            "'Lobby: Dashboard' is sufficient. SMART monitoring additionally "
            "requires the 'Services: SMART' privilege on OPNsense. Gateways "
            "need 'System: Gateways', WireGuard peers 'VPN: WireGuard: "
            "Status', DHCP pool usage 'Services: DHCP: Kea(v4)' and/or "
            "'Services: Dnsmasq DNS/DHCP: Settings'. Missing privileges only "
            "disable the affected services. WARNING: OPNsense privileges are "
            "not read-only - e.g. 'System: Firmware' also allows firmware "
            "updates and reboot, 'Status: Services' starting/stopping "
            "services. 'System: Deny config write' does not block these. "
            "Treat the API secret like an admin credential."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API key"),
                    help_text=Help("The OPNsense API key (used as username). "
                                   "May reference the password store."),
                    migrate=migrate_to_password,
                ),
            ),
            "api_secret": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API secret"),
                    help_text=Help("The OPNsense API secret (used as password)."),
                    migrate=migrate_to_password,
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    help_text=Help("TCP port of the OPNsense web GUI / API."),
                    prefill=DefaultValue(8443),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    help_text=Help(
                        "Enable this if the OPNsense uses a self-signed "
                        "certificate (default for a fresh install)."
                    ),
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
            "audit_interval": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Package audit interval (minutes)"),
                    help_text=Help(
                        "How often the agent triggers a package audit "
                        "('pkg audit', known vulnerabilities in installed "
                        "packages) on OPNsense. The audit fetches the "
                        "vulnerability database on the firewall, so it runs "
                        "only every N minutes; the result is cached on the "
                        "Checkmk site. 0 disables the audit."
                    ),
                    prefill=DefaultValue(360),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=10080),),
                ),
            ),
        },
    )


rule_spec_opnsense = SpecialAgent(
    name="opnsense",
    title=Title("OPNsense firewall (REST API)"),
    topic=Topic.NETWORKING,
    parameter_form=_formspec,
)
