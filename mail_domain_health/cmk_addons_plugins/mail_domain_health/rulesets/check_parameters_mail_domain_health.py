#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Check parameter rulesets for the mail_domain_health services."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    LevelDirection,
    ServiceState,
    SimpleLevels,
    SingleChoice,
    SingleChoiceElement,
    String,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic

# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------


def _parameter_form_spf() -> Dictionary:
    return Dictionary(
        elements={
            "state_no_record": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no SPF record is published"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_multiple_records": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if multiple SPF records are published"),
                    help_text=Help(
                        "More than one 'v=spf1' record is an RFC violation and makes "
                        "SPF evaluation fail entirely (permerror)."
                    ),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "allowed_all_qualifiers": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Required 'all' policy"),
                    elements=[
                        SingleChoiceElement(
                            name="fail_only",
                            title=Title("Require hard fail (-all)"),
                        ),
                        SingleChoiceElement(
                            name="softfail_or_fail",
                            title=Title("Require soft fail or hard fail (~all or -all)"),
                        ),
                        SingleChoiceElement(
                            name="any",
                            title=Title("Do not check the 'all' qualifier"),
                        ),
                    ],
                    prefill=DefaultValue("softfail_or_fail"),
                ),
            ),
            "state_bad_all": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the 'all' mechanism violates the required policy"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "lookup_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on DNS lookups caused by the record"),
                    help_text=Help(
                        "RFC 7208 limits SPF evaluation to 10 DNS lookups. Records "
                        "exceeding the limit evaluate to permerror at the receiver, "
                        "i.e. SPF is broken."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((10, 11)),
                ),
            ),
            "state_record_problems": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State on record problems"),
                    help_text=Help(
                        "Problems like unknown mechanisms, include targets without an "
                        "SPF record, or include loops."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "expected_record": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("Expected record content"),
                    help_text=Help(
                        "If set, the published record is compared verbatim against "
                        "this string. Useful to detect unauthorized DNS changes."
                    ),
                ),
            ),
            "state_record_mismatch": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the record differs from the expected record"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_spf = CheckParameters(
    name="mail_domain_health_spf",
    title=Title("Mail domain health: SPF record"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_spf,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------


def _parameter_form_dmarc() -> Dictionary:
    return Dictionary(
        elements={
            "state_no_record": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no DMARC record is published"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_multiple_records": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if multiple DMARC records are published"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "min_policy": DictElement(
                required=False,
                parameter_form=SingleChoice(
                    title=Title("Minimum required policy (p=)"),
                    elements=[
                        SingleChoiceElement(name="none", title=Title("none (monitoring only)")),
                        SingleChoiceElement(name="quarantine", title=Title("quarantine")),
                        SingleChoiceElement(name="reject", title=Title("reject")),
                    ],
                    prefill=DefaultValue("quarantine"),
                ),
            ),
            "state_weak_policy": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the policy is weaker than required"),
                    help_text=Help(
                        "Also applies to a weaker subdomain policy (sp=) and to "
                        "records with pct= below 100."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "require_rua": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Require aggregate report address"),
                    label=Label("An rua= tag must be present"),
                    prefill=DefaultValue(True),
                ),
            ),
            "state_no_rua": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no rua= tag is present"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_dmarc = CheckParameters(
    name="mail_domain_health_dmarc",
    title=Title("Mail domain health: DMARC record"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_dmarc,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# RBL
# ---------------------------------------------------------------------------


def _parameter_form_rbl() -> Dictionary:
    return Dictionary(
        elements={
            "listed_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on the number of blacklist listings"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((1, 2)),
                ),
            ),
            "error_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on the number of failed DNSBL queries"),
                    help_text=Help(
                        "Failed queries are timeouts, DNS errors, implausible answers "
                        "from dead lists, and queries refused by the list operator "
                        "(e.g. Spamhaus when queried through a public resolver). "
                        "By default these do not affect the service state."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((1, 3)),
                ),
            ),
            "state_unresolved": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the host name does not resolve to any IP"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_fcrdns_fail": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State on forward-confirmed reverse DNS (FCrDNS) failure"),
                    help_text=Help(
                        "Only relevant when FCrDNS verification is enabled in the "
                        "special agent rule. Triggered when an IP's PTR name is missing "
                        "or does not resolve back to that IP - a common cause of mail "
                        "being rejected by receiving servers."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_rbl = CheckParameters(
    name="mail_domain_health_rbl",
    title=Title("Mail domain health: DNSBL/RBL listings"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_rbl,
    condition=HostAndItemCondition(item_title=Title("IP address")),
)


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------


def _parameter_form_dkim() -> Dictionary:
    return Dictionary(
        elements={
            "require_any_selector": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Require at least one selector present"),
                    label=Label("Alert if none of the configured selectors resolve"),
                    prefill=DefaultValue(True),
                ),
            ),
            "state_no_selector": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no configured selector is present"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "min_key_bits": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Minimum RSA key size (bits)"),
                    help_text=Help("RSA keys smaller than this are flagged. 2048 is recommended."),
                    prefill=DefaultValue(2048),
                ),
            ),
            "state_weak_key": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if an RSA key is smaller than the minimum"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_revoked": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if a selector key is revoked (empty p=)"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_testing": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if a selector is in test mode (t=y)"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_invalid": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if a selector record is invalid"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_dkim = CheckParameters(
    name="mail_domain_health_dkim",
    title=Title("Mail domain health: DKIM records"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_dkim,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# Domain-based blacklists
# ---------------------------------------------------------------------------


def _parameter_form_domain_bl() -> Dictionary:
    return Dictionary(
        elements={
            "listed_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on the number of blacklist listings"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((1, 2)),
                ),
            ),
            "error_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels on the number of failed queries"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((1, 3)),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_domain_bl = CheckParameters(
    name="mail_domain_health_domain_bl",
    title=Title("Mail domain health: domain-based blacklists"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_domain_bl,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# MTA-STS + TLS-RPT
# ---------------------------------------------------------------------------


def _parameter_form_mta_sts() -> Dictionary:
    return Dictionary(
        elements={
            "state_no_sts": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no MTA-STS record is published"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_policy_error": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the policy file is missing or invalid"),
                    help_text=Help(
                        "Triggered when the domain advertises MTA-STS but the HTTPS "
                        "policy file cannot be fetched, has an invalid mode, or lists "
                        "no mx hosts."
                    ),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_not_enforcing": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the policy mode is 'testing' or 'none'"),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
            "require_tls_rpt": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Require a TLS-RPT record"),
                    label=Label("A _smtp._tls (TLS-RPT) record must be present"),
                    prefill=DefaultValue(True),
                ),
            ),
            "state_no_tls_rpt": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no TLS-RPT record is present"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "check_mx_match": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Compare policy mx list against the actual MX records"),
                    label=Label("Alert if a real MX host is not covered by the policy"),
                    prefill=DefaultValue(True),
                ),
            ),
            "state_mx_mismatch": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if an MX host is not covered by the policy"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "min_max_age": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("Minimum policy max_age (seconds)"),
                    help_text=Help(
                        "A short max_age weakens MTA-STS because caches expire quickly. "
                        "RFC 8461 recommends a large value; 604800 (one week) is a "
                        "common minimum for production."
                    ),
                    unit_symbol="s",
                    prefill=DefaultValue(604800),
                ),
            ),
            "state_short_max_age": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if max_age is below the minimum"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_id_changed": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State when the policy id changes between checks"),
                    help_text=Help(
                        "A changed id is normal after you update the policy; the "
                        "default is OK (informational). Raise it if you want to be "
                        "alerted to unexpected policy changes."
                    ),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_mta_sts = CheckParameters(
    name="mail_domain_health_mta_sts",
    title=Title("Mail domain health: MTA-STS / TLS-RPT"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_mta_sts,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# DANE / TLSA
# ---------------------------------------------------------------------------


def _parameter_form_dane() -> Dictionary:
    return Dictionary(
        elements={
            "state_no_tlsa": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if an MX host publishes no TLSA record"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "require_dnssec": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Require TLSA records to be DNSSEC-validated"),
                    label=Label("Alert if TLSA records are not covered by the AD bit"),
                    prefill=DefaultValue(True),
                ),
            ),
            "state_not_signed": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if TLSA present but not DNSSEC-validated"),
                    help_text=Help("DANE without DNSSEC provides no security guarantee."),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_mismatch": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the live certificate does not match TLSA"),
                    help_text=Help("Only evaluated when live verification is enabled."),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "state_no_cert": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the certificate could not be retrieved"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_dane = CheckParameters(
    name="mail_domain_health_dane",
    title=Title("Mail domain health: DANE/TLSA"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_dane,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# BIMI
# ---------------------------------------------------------------------------


def _parameter_form_bimi() -> Dictionary:
    return Dictionary(
        elements={
            "state_no_record": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no BIMI record is published"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_no_logo": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the BIMI record has no logo URL (l=)"),
                    prefill=DefaultValue(ServiceState.CRIT),
                ),
            ),
            "require_vmc": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Require a VMC certificate"),
                    label=Label("An a= (VMC) tag must be present"),
                    prefill=DefaultValue(False),
                ),
            ),
            "state_no_vmc": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if no VMC certificate URL (a=) is present"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_logo_unreachable": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the logo URL is not reachable"),
                    help_text=Help("Only evaluated when URL reachability checking is enabled."),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_logo_not_svg": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the logo is reachable but not SVG"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "state_vmc_unreachable": DictElement(
                required=False,
                parameter_form=ServiceState(
                    title=Title("State if the VMC URL is not reachable"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_bimi = CheckParameters(
    name="mail_domain_health_bimi",
    title=Title("Mail domain health: BIMI record"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_bimi,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)


# ---------------------------------------------------------------------------
# Domain registration expiry (RDAP)
# ---------------------------------------------------------------------------


def _parameter_form_rdap() -> Dictionary:
    return Dictionary(
        elements={
            "age_levels": DictElement(
                required=False,
                parameter_form=SimpleLevels(
                    title=Title("Lower levels on days until expiry"),
                    help_text=Help("Warn/critical when the registration expires within N days."),
                    form_spec_template=Integer(unit_symbol="days"),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue((30, 14)),
                ),
            ),
        },
    )


rule_spec_mail_domain_health_rdap = CheckParameters(
    name="mail_domain_health_rdap",
    title=Title("Mail domain health: domain registration expiry"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form_rdap,
    condition=HostAndItemCondition(item_title=Title("Domain")),
)
