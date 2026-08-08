#!/usr/bin/env python3
"""WATO ruleset for the openWB special agent."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    DictGroup,
    Dictionary,
    Integer,
    Password,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic

try:
    # Checkmk >= 2.4 GUI-internal API: lets us force the "Discovery options"
    # group to render its fields stacked vertically instead of the default
    # horizontal (side-by-side) layout. This module lives under
    # cmk.gui.form_specs.unstable and is NOT part of the stable
    # cmk.rulesets.v1 plugin API, so it may move or disappear in future
    # Checkmk releases without notice. Fall back to the plain DictGroup
    # (horizontal layout) if it's unavailable.
    from cmk.gui.form_specs.unstable.dictionary_extended import DictGroupExtended
    from cmk.shared_typing.vue_formspec_components import DictionaryGroupLayout

    _DISCOVERY_GROUP = DictGroupExtended(
        title=Title("Discovery options"),
        help_text=Help(
            "Chargepoints, counters, batteries and PV inverters are "
            "auto-discovered by probing numeric device IDs from 0 up to "
            "the configured maximum. Lower these values to speed up "
            "discovery, or raise them if the wallbox has more devices "
            "than the default range covers."
        ),
        layout=DictionaryGroupLayout.vertical,
    )
except ImportError:
    _DISCOVERY_GROUP = DictGroup(
        title=Title("Discovery options"),
        help_text=Help(
            "Chargepoints, counters, batteries and PV inverters are "
            "auto-discovered by probing numeric device IDs from 0 up to "
            "the configured maximum. Lower these values to speed up "
            "discovery, or raise them if the wallbox has more devices "
            "than the default range covers."
        ),
    )


def _formspec():
    return Dictionary(
        title=Title("openWB wallbox (simpleAPI)"),
        help_text=Help(
            "Poll an openWB wallbox over its read-only simpleAPI HTTP "
            "endpoint. Chargepoints, counters, batteries and PV inverters "
            "are auto-discovered by probing a configurable range of "
            "numeric device IDs, since the simpleAPI has no built-in "
            "'list all devices' call. Only GET requests are used — this "
            "agent never writes to the wallbox. Username/password are "
            "only required if the openWB web UI has login protection "
            "enabled."
        ),
        elements={
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTP(S) port"),
                    help_text=Help("TCP port of the openWB web UI / simpleAPI."),
                    prefill=DefaultValue(80),
                    custom_validate=(validators.NumberInRange(min_value=1, max_value=65535),),
                ),
            ),
            "https": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Use HTTPS"),
                    prefill=DefaultValue(False),
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Disable TLS certificate verification"),
                    help_text=Help("Only relevant if HTTPS is enabled and the "
                                   "openWB uses a self-signed certificate."),
                    prefill=DefaultValue(True),
                ),
            ),
            "username": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Username"),
                    help_text=Help("Only needed if login protection is enabled "
                                   "on the openWB web UI."),
                ),
            ),
            "password": DictElement(
                required=False,
                parameter_form=Password(
                    title=Title("Password"),
                    help_text=Help("Only needed if login protection is enabled "
                                   "on the openWB web UI."),
                    migrate=migrate_to_password,
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
            "max_chargepoint_id": DictElement(
                required=False,
                group=_DISCOVERY_GROUP,
                parameter_form=Integer(
                    title=Title("Highest chargepoint ID to probe"),
                    help_text=Help("Chargepoint IDs 0..N are probed for "
                                   "auto-discovery."),
                    prefill=DefaultValue(9),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=99),),
                ),
            ),
            "max_counter_id": DictElement(
                required=False,
                group=_DISCOVERY_GROUP,
                parameter_form=Integer(
                    title=Title("Highest counter ID to probe"),
                    prefill=DefaultValue(19),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=99),),
                ),
            ),
            "max_battery_id": DictElement(
                required=False,
                group=_DISCOVERY_GROUP,
                parameter_form=Integer(
                    title=Title("Highest battery ID to probe"),
                    prefill=DefaultValue(19),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=99),),
                ),
            ),
            "max_pv_id": DictElement(
                required=False,
                group=_DISCOVERY_GROUP,
                parameter_form=Integer(
                    title=Title("Highest PV inverter ID to probe"),
                    prefill=DefaultValue(19),
                    custom_validate=(validators.NumberInRange(min_value=0, max_value=99),),
                ),
            ),
        },
    )


rule_spec_openwb = SpecialAgent(
    name="openwb",
    title=Title("openWB wallbox (simpleAPI)"),
    topic=Topic.SERVER_HARDWARE,
    parameter_form=_formspec,
)
