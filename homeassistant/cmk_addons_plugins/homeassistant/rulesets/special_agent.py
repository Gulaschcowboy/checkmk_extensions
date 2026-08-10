#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    Integer,
    Password,
    String,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _migrate_ruleset(value):
    """Migrate stored Home Assistant rules from older package versions."""
    if isinstance(value, dict) and "ignore_unavailable" not in value:
        return {**value, "ignore_unavailable": False}
    return value


def _formspec():
    return Dictionary(
        migrate=_migrate_ruleset,
        title=Title("Home Assistant"),
        help_text=Help(
            "Fetch Home Assistant sensor data and create area/room-based Checkmk piggyback hosts."
        ),
        elements={
            "url": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Home Assistant URL"),
                    help_text=Help("Base URL, for example https://homeassistant.example.org:8123"),
                    prefill=DefaultValue("http://homeassistant.local:8123"),
                ),
            ),
            "token": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("Long-lived access token"),
                    help_text=Help("Home Assistant long-lived access token. The Checkmk password store can be used."),
                    migrate=migrate_to_password,
                ),
            ),
            "verify_tls": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Verify TLS certificate"),
                    label=Label("Verify the Home Assistant HTTPS certificate"),
                    prefill=DefaultValue(True),
                ),
            ),
            "domains": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Entity domains"),
                    help_text=Help("Comma-separated Home Assistant domains to import."),
                    prefill=DefaultValue("sensor,binary_sensor"),
                ),
            ),
            "include_regex": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Include regular expression"),
                    help_text=Help("Optional regex matched against entity ID and friendly name."),
                ),
            ),
            "exclude_regex": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Exclude regular expression"),
                    help_text=Help("Optional regex matched against entity ID and friendly name."),
                ),
            ),
            "ignore_unavailable": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Ignore unavailable entities"),
                    label=Label("Do not import Home Assistant entities whose state is unavailable"),
                    help_text=Help("When enabled, entities with the exact Home Assistant state unavailable are filtered before piggyback data is generated. Entities in state unknown are still imported."),
                    prefill=DefaultValue(False),
                ),
            ),
            "host_prefix": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Piggyback host prefix"),
                    help_text=Help("Lowercase letters, digits and hyphens only. Area names are converted to readable Checkmk host names such as ha-living-room."),
                    prefill=DefaultValue("ha-"),
                ),
            ),
            "timeout": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("API timeout in seconds"),
                    prefill=DefaultValue(10.0),
                ),
            ),
            "stale_after": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Warn when entity data is older than seconds"),
                    help_text=Help("Use 0 to disable stale-data warnings."),
                    prefill=DefaultValue(0.0),
                ),
            ),
            "max_hosts": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Maximum generated piggyback hosts"),
                    help_text=Help("Safety limit. Use 0 for unlimited."),
                    prefill=DefaultValue(150),
                ),
            ),
            "max_entities": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Maximum imported entities"),
                    help_text=Help("Safety limit to protect the Checkmk service budget. Use 0 for unlimited."),
                    prefill=DefaultValue(450),
                ),
            ),
        },
    )


rule_spec_homeassistant = SpecialAgent(
    topic=Topic.GENERAL,
    name="homeassistant",
    title=Title("Home Assistant"),
    parameter_form=_formspec,
)
