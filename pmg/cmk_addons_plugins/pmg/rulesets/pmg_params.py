#!/usr/bin/env python3
"""WATO check parameter rulesets for Proxmox Mail Gateway (PMG) checks."""
from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
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


# --- Mail throughput / junk ratio -----------------------------------------
def _mail_form():
    return Dictionary(
        title=Title("PMG mail statistics"),
        elements={
            "junk_percent_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Junk ratio (PMG-reported) of incoming mail"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(unit_symbol="%"),
                    prefill_fixed_levels=DefaultValue((50.0, 80.0)),
                ),
            ),
        },
    )


rule_spec_pmg_mail = CheckParameters(
    name="pmg_mail",
    title=Title("PMG mail statistics"),
    topic=Topic.NETWORKING,
    parameter_form=_mail_form,
    condition=HostCondition(),
)


# --- SMTP rejects (RBL / PREGREET) -----------------------------------------
def _rejects_form():
    return Dictionary(
        title=Title("PMG SMTP early rejects"),
        elements={
            "levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Total rejects (RBL + PREGREET) over the reporting window"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((1000.0, 5000.0)),
                ),
            ),
        },
    )


rule_spec_pmg_rejects = CheckParameters(
    name="pmg_rejects",
    title=Title("PMG SMTP early rejects"),
    topic=Topic.NETWORKING,
    parameter_form=_rejects_form,
    condition=HostCondition(),
)


# --- Postfix queue depth ----------------------------------------------------
def _queue_form():
    return Dictionary(
        title=Title("PMG Postfix queue depth"),
        elements={
            "levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Number of mails in this queue"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((200.0, 1000.0)),
                ),
            ),
        },
    )


rule_spec_pmg_queue = CheckParameters(
    name="pmg_queue",
    title=Title("PMG Postfix queue depth"),
    topic=Topic.NETWORKING,
    parameter_form=_queue_form,
    condition=HostAndItemCondition(item_title=Title("Queue name")),
)


# --- Quarantine (spam / virus) ----------------------------------------------
def _quarantine_spam_form():
    return Dictionary(
        title=Title("PMG spam quarantine size"),
        elements={
            "count_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Number of quarantined mails"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((10000.0, 50000.0)),
                ),
            ),
        },
    )


rule_spec_pmg_quarantine_spam = CheckParameters(
    name="pmg_quarantine_spam",
    title=Title("PMG spam quarantine size"),
    topic=Topic.NETWORKING,
    parameter_form=_quarantine_spam_form,
    condition=HostCondition(),
)


def _quarantine_virus_form():
    return Dictionary(
        title=Title("PMG virus quarantine size"),
        elements={
            "count_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Number of quarantined mails"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((1.0, 1.0)),
                ),
            ),
        },
    )


rule_spec_pmg_quarantine_virus = CheckParameters(
    name="pmg_quarantine_virus",
    title=Title("PMG virus quarantine size"),
    topic=Topic.NETWORKING,
    parameter_form=_quarantine_virus_form,
    condition=HostCondition(),
)


# --- ClamAV database age ----------------------------------------------------
def _clamav_form():
    return Dictionary(
        title=Title("PMG ClamAV database age"),
        elements={
            "age_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Age of the virus signature database"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
                    ),
                    prefill_fixed_levels=DefaultValue((172800.0, 604800.0)),
                ),
            ),
        },
    )


rule_spec_pmg_clamav = CheckParameters(
    name="pmg_clamav",
    title=Title("PMG ClamAV database age"),
    topic=Topic.NETWORKING,
    parameter_form=_clamav_form,
    condition=HostAndItemCondition(item_title=Title("Database type")),
)


# --- SpamAssassin update state -----------------------------------------------
def _spamassassin_form():
    return Dictionary(
        title=Title("PMG SpamAssassin rule update status"),
        elements={
            "update_avail_state": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when a rule update is available"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_pmg_spamassassin = CheckParameters(
    name="pmg_spamassassin",
    title=Title("PMG SpamAssassin rule update status"),
    topic=Topic.NETWORKING,
    parameter_form=_spamassassin_form,
    condition=HostAndItemCondition(item_title=Title("Rule channel")),
)


# --- Pending package updates --------------------------------------------------
def _updates_form():
    return Dictionary(
        title=Title("PMG pending package updates"),
        elements={
            "levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Number of pending package updates"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_fixed_levels=DefaultValue((1.0, 20.0)),
                ),
            ),
        },
    )


rule_spec_pmg_updates = CheckParameters(
    name="pmg_updates",
    title=Title("PMG pending package updates"),
    topic=Topic.NETWORKING,
    parameter_form=_updates_form,
    condition=HostCondition(),
)


# --- Certificate expiry --------------------------------------------------------
def _certificates_form():
    return Dictionary(
        title=Title("PMG certificate expiry"),
        help_text=Help("Levels are checked against the remaining validity time "
                       "-- lower remaining time is worse."),
        elements={
            "expiry_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Remaining validity before WARN/CRIT"),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
                    ),
                    prefill_fixed_levels=DefaultValue((30 * 86400.0, 7 * 86400.0)),
                ),
            ),
        },
    )


rule_spec_pmg_certificates = CheckParameters(
    name="pmg_certificates",
    title=Title("PMG certificate expiry"),
    topic=Topic.NETWORKING,
    parameter_form=_certificates_form,
    condition=HostAndItemCondition(item_title=Title("Certificate subject")),
)
