#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Ruleset for the 'mail_domain_health' special agent (Setup > Agents > Other integrations)."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Label, Message, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    InputHint,
    List,
    String,
    validators,
)
from cmk.rulesets.v1.form_specs.validators import ValidationError
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _validate_dkim(value: object) -> None:
    """DKIM only produces services if at least one selector is configured."""
    if not isinstance(value, dict):
        return
    has_global = bool(value.get("selectors"))
    has_per_domain = bool(value.get("per_domain"))
    if not has_global and not has_per_domain:
        raise ValidationError(
            Message(
                "Enter at least one DKIM selector - a global selector or a "
                "per-domain selector. Without any selector no DKIM service is created."
            )
        )


def _migrate(value: object) -> dict:
    """Migrate stored rules from earlier versions.

    - 'dnssec' was removed in 1.3.0 (DNSSEC moved to the separate dnssec_health
      plugin); drop the obsolete key so old rules validate.
    - 'spf'/'dmarc' became explicit toggles in 1.3.0. Older rules always ran
      both, so default them to True when absent to preserve behaviour.
    - In 1.4.0 the flat 'targets'/'resolve_mx'/'rbls' keys were grouped under a
      nested 'rbl' dictionary; move them there if present at the top level.
    """
    if not isinstance(value, dict):
        return value  # nothing we can do; let normal validation handle it
    migrated = dict(value)
    migrated.pop("dnssec", None)
    migrated.setdefault("spf", True)
    migrated.setdefault("dmarc", True)

    # Group the former top-level RBL keys under 'rbl'.
    if "rbl" not in migrated:
        rbl_group: dict = {}
        for key in ("targets", "resolve_mx", "rbls"):
            if key in migrated:
                rbl_group[key] = migrated.pop(key)
        if rbl_group:
            migrated["rbl"] = rbl_group
    else:
        # already nested; just make sure stray top-level copies don't linger
        for key in ("targets", "resolve_mx", "rbls"):
            migrated.pop(key, None)

    return migrated


def _parameter_form() -> Dictionary:
    return Dictionary(
        migrate=_migrate,
        help_text=Help(
            "Monitor mail security DNS data: SPF and DMARC records of your domains "
            "and DNSBL (blacklist) listings of your mail server IP addresses. "
            "All data is collected via DNS queries from the Checkmk site; no agent "
            "needs to be installed anywhere. Assign this rule to a host of your "
            "choice (e.g. a dedicated host without a Checkmk agent). "
            "Note: Spamhaus refuses queries coming from public resolvers such as "
            "8.8.8.8 or 1.1.1.1 - use your own recursive resolver."
        ),
        elements={
            "domains": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Domains to monitor"),
                    help_text=Help(
                        "Required. The domains checked by this rule. Which checks run "
                        "against them is controlled by the toggles below (SPF and DMARC "
                        "are on by default; the rest are optional). If you disable SPF "
                        "and DMARC and enable only, say, DANE, then only DANE services "
                        "are created for these domains. Note: the DNSBL/RBL checks are "
                        "driven by the 'Hosts / IP addresses' field or the 'check the MX "
                        "hosts' option below, not by this list."
                    ),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                        prefill=InputHint("example.com"),
                    ),
                    add_element_label=Label("Add domain"),
                ),
            ),
            "spf": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Check SPF records"),
                    label=Label("Create an 'SPF <domain>' service for each domain"),
                    prefill=DefaultValue(True),
                ),
            ),
            "dmarc": DictElement(
                required=True,
                parameter_form=BooleanChoice(
                    title=Title("Check DMARC records"),
                    label=Label("Create a 'DMARC <domain>' service for each domain"),
                    prefill=DefaultValue(True),
                ),
            ),
            "rbl": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("DNSBL / RBL checks (optional)"),
                    help_text=Help(
                        "Check mail server IPs against DNS blacklists (DNSBLs). "
                        "Enable this and configure the targets and the zones to query. "
                        "No zones are shipped by default - see 'DNSBL zones to query' "
                        "for a list you can copy. Note: the usefulness of public "
                        "blacklists is declining, because the large mailbox providers "
                        "(Gmail, Microsoft) increasingly rely on their own internal "
                        "reputation rather than public DNSBLs. A clean DNSBL result "
                        "therefore does not guarantee good deliverability; treat this "
                        "as a hygiene signal (loud when it fires, weakly informative "
                        "when clean)."
                    ),
                    elements={
                        "targets": DictElement(
                            required=False,
                            parameter_form=List(
                                title=Title("Hosts / IP addresses to check against DNSBLs"),
                                help_text=Help(
                                    "Host names or public IPv4/IPv6 addresses of your "
                                    "outbound mail servers. Prefer host names: the "
                                    "service item then stays stable "
                                    "('RBL mail.example.com') even when the underlying "
                                    "A/AAAA records change, and all current addresses of "
                                    "the name are checked. One service "
                                    "'RBL <name-or-ip>' is created per entry."
                                ),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                    prefill=InputHint("mail.example.com"),
                                ),
                                add_element_label=Label("Add host / IP"),
                            ),
                        ),
                        "resolve_mx": DictElement(
                            required=False,
                            parameter_form=BooleanChoice(
                                title=Title("Additionally check the MX hosts of each domain"),
                                label=Label(
                                    "Resolve the MX records of every monitored domain "
                                    "and check the MX host names against the DNSBLs as "
                                    "well"
                                ),
                                prefill=DefaultValue(False),
                            ),
                        ),
                        "rbls": DictElement(
                            required=False,
                            parameter_form=List(
                                title=Title("DNSBL zones to query"),
                                help_text=Help(
                                    "The DNS blacklist zones each IP is checked against. "
                                    "No zones are built in - you must enter the ones you "
                                    "want, and you are responsible for keeping the list "
                                    "current (blacklists are shut down or abandoned over "
                                    "time). Add one zone per entry. Commonly used zones "
                                    "to copy from (verify they still fit your needs): "
                                    "zen.spamhaus.org, bl.spamcop.net, "
                                    "b.barracudacentral.org, psbl.surriel.com, "
                                    "all.s5h.net, dnsbl.dronebl.org. Important: "
                                    "zen.spamhaus.org (and most large lists) refuse "
                                    "queries from public resolvers such as 8.8.8.8 or "
                                    "1.1.1.1 and above free usage limits - set your own "
                                    "recursive resolver under 'DNS servers to use', and "
                                    "raise the check interval to stay within rate "
                                    "limits. For a broader community-maintained "
                                    "reference list, see Matteo Corti's check_rbl.ini "
                                    "(github.com/matteocorti/check_rbl). If no zones are "
                                    "configured, no RBL service is created."
                                ),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                    prefill=InputHint("zen.spamhaus.org"),
                                ),
                                add_element_label=Label("Add DNSBL zone"),
                            ),
                        ),
                    },
                ),
            ),
            "nameservers": DictElement(
                required=False,
                parameter_form=List(
                    title=Title("DNS servers to use"),
                    help_text=Help(
                        "IP addresses of the recursive DNS servers to query. "
                        "If empty, the resolvers from /etc/resolv.conf of the "
                        "Checkmk server are used."
                    ),
                    element_template=String(
                        custom_validate=(validators.LengthInRange(min_value=1),),
                        prefill=InputHint("192.168.1.53"),
                    ),
                    add_element_label=Label("Add DNS server"),
                ),
            ),
            "dkim": DictElement(
                required=False,
                parameter_form=Dictionary(
                    custom_validate=(_validate_dkim,),
                    title=Title("Check DKIM public keys (optional)"),
                    help_text=Help(
                        "When enabled you must enter at least one selector (global or "
                        "per-domain) - DKIM selectors cannot be discovered from DNS. "
                        "Global selectors are looked up for every domain "
                        "(<selector>._domainkey.<domain>); per-domain selectors are "
                        "added on top for the given domain. One service 'DKIM <domain>' "
                        "is created per domain; selectors that do not exist for a given "
                        "domain are reported as absent."
                    ),
                    elements={
                        "selectors": DictElement(
                            required=False,
                            parameter_form=List(
                                title=Title("Global DKIM selectors (applied to all domains)"),
                                help_text=Help(
                                    "A DKIM selector is the label in "
                                    "<selector>._domainkey.<domain> that points to a "
                                    "public key. It is provider-specific and cannot be "
                                    "discovered from DNS, so list the selectors your "
                                    "senders actually use. Common values: Google "
                                    "Workspace 'google' (and 'google2' after a key "
                                    "rotation), Microsoft 365 'selector1' and "
                                    "'selector2', SendGrid 's1'/'s2', Mailchimp 'k1'. "
                                    "A selector name is only a hint - a domain can use "
                                    "'google' without using Google. The reliable way to "
                                    "find yours: send a message and read the s= tag of "
                                    "the DKIM-Signature header (the d= tag must match "
                                    "the domain). Add one entry per selector."
                                ),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                    prefill=InputHint("e.g. google, selector1, s1, k1"),
                                ),
                                add_element_label=Label("Add selector"),
                            ),
                        ),
                        "per_domain": DictElement(
                            required=False,
                            parameter_form=List(
                                title=Title("Per-domain selectors (added for one domain)"),
                                help_text=Help(
                                    "Use this for domains whose selectors differ from "
                                    "the global set, e.g. a domain on a different email "
                                    "provider. See the global-selectors help for how to "
                                    "find a selector (the s= tag of the DKIM-Signature "
                                    "header)."
                                ),
                                element_template=Dictionary(
                                    elements={
                                        "domain": DictElement(
                                            required=True,
                                            parameter_form=String(
                                                title=Title("Domain"),
                                                custom_validate=(
                                                    validators.LengthInRange(min_value=1),
                                                ),
                                                prefill=InputHint("example.com"),
                                            ),
                                        ),
                                        "selectors": DictElement(
                                            required=True,
                                            parameter_form=List(
                                                title=Title("Selectors for this domain"),
                                                element_template=String(
                                                    custom_validate=(
                                                        validators.LengthInRange(min_value=1),
                                                    ),
                                                    prefill=InputHint("e.g. selector1, s1, k1"),
                                                ),
                                                add_element_label=Label("Add selector"),
                                            ),
                                        ),
                                    },
                                ),
                                add_element_label=Label("Add domain"),
                            ),
                        ),
                    },
                ),
            ),
            "domain_blacklists": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("Check domain-based blacklists (optional)"),
                    help_text=Help(
                        "Query domain-reputation blacklists (DBL/SURBL/URIBL) for each "
                        "monitored domain. This catches your domain being blacklisted "
                        "independently of any mail server IP. One service "
                        "'Domain blacklist <domain>' is created per domain. You must "
                        "configure at least one zone (there are no built-in defaults); "
                        "if none are set, no service is created."
                    ),
                    elements={
                        "zones": DictElement(
                            required=False,
                            parameter_form=List(
                                title=Title("Blacklist zones"),
                                help_text=Help(
                                    "Domain-reputation blacklist zones. No zones are "
                                    "built in - enter the ones you want and keep the "
                                    "list current. Add one zone per entry. Commonly "
                                    "used zones to copy from (verify they still fit): "
                                    "dbl.spamhaus.org, multi.surbl.org, multi.uribl.com. "
                                    "As with the IP DNSBLs, dbl.spamhaus.org refuses "
                                    "queries from public resolvers - use your own "
                                    "recursive resolver under 'DNS servers to use'."
                                ),
                                element_template=String(
                                    custom_validate=(validators.LengthInRange(min_value=1),),
                                    prefill=InputHint("dbl.spamhaus.org"),
                                ),
                                add_element_label=Label("Add zone"),
                            ),
                        ),
                    },
                ),
            ),
            "fcrdns": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Verify forward-confirmed reverse DNS (optional)"),
                    label=Label(
                        "For every checked mail server IP, verify that its PTR name "
                        "resolves back to the same IP (FCrDNS). Reported within the "
                        "RBL service."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
            "mta_sts": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Check MTA-STS and TLS-RPT (optional)"),
                    label=Label(
                        "Check the _mta-sts TXT record, fetch and validate the MTA-STS "
                        "policy file over HTTPS, and check the _smtp._tls (TLS-RPT) "
                        "record. Creates one service 'MTA-STS <domain>' per domain. "
                        "Requires outbound HTTPS from the Checkmk server."
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
            "dane": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("Check DANE/TLSA (optional)"),
                    help_text=Help(
                        "Check TLSA records at _25._tcp.<mxhost> for each MX host of a "
                        "domain. DANE is only meaningful when the TLSA records are "
                        "DNSSEC-signed. Creates one service 'DANE <domain>' per domain."
                    ),
                    elements={
                        "verify_certificate": DictElement(
                            required=False,
                            parameter_form=BooleanChoice(
                                title=Title("Verify the live certificate"),
                                label=Label(
                                    "Connect to each MX on port 25, perform STARTTLS, "
                                    "and check the presented certificate against the "
                                    "TLSA records. Requires outbound port 25."
                                ),
                                prefill=DefaultValue(False),
                            ),
                        ),
                    },
                ),
            ),
            "bimi": DictElement(
                required=False,
                parameter_form=Dictionary(
                    title=Title("Check BIMI (optional)"),
                    help_text=Help(
                        "Check the BIMI record at <selector>._bimi.<domain>. BIMI is "
                        "only honored when the domain has DMARC at enforcement. Creates "
                        "one service 'BIMI <domain>' per domain."
                    ),
                    elements={
                        "selector": DictElement(
                            required=True,
                            parameter_form=String(
                                title=Title("BIMI selector"),
                                help_text=Help(
                                    "The BIMI selector to look up, i.e. "
                                    "<selector>._bimi.<domain>. Defaults to 'default'."
                                ),
                                custom_validate=(validators.LengthInRange(min_value=1),),
                                prefill=DefaultValue("default"),
                            ),
                        ),
                        "check_reachability": DictElement(
                            required=False,
                            parameter_form=BooleanChoice(
                                title=Title("Check logo/VMC URL reachability"),
                                label=Label(
                                    "Fetch the logo (l=) and VMC (a=) URLs over HTTPS "
                                    "and verify they are reachable (and the logo is SVG). "
                                    "Requires outbound HTTPS."
                                ),
                                prefill=DefaultValue(False),
                            ),
                        ),
                    },
                ),
            ),
            "rdap": DictElement(
                required=False,
                parameter_form=BooleanChoice(
                    title=Title("Check domain registration expiry via RDAP (optional)"),
                    label=Label(
                        "Query RDAP for each domain's registration expiry date and "
                        "alert as it approaches. Creates one service "
                        "'Domain expiry <domain>' per domain. Requires outbound HTTPS. "
                        "Not all TLDs expose an expiry date via RDAP."
                    ),
                    prefill=DefaultValue(False),
                ),
            ),
            "http_timeout": DictElement(
                required=False,
                parameter_form=Float(
                    title=Title("Timeout for HTTPS fetches (MTA-STS, RDAP) in seconds"),
                    prefill=DefaultValue(10.0),
                    custom_validate=(validators.NumberInRange(min_value=1.0, max_value=120.0),),
                ),
            ),
            "timeout": DictElement(
                required=False,
                parameter_form=Float(
                    title=Title("Timeout per DNS query (seconds)"),
                    prefill=DefaultValue(5.0),
                    custom_validate=(validators.NumberInRange(min_value=0.5, max_value=60.0),),
                ),
            ),
        },
    )


rule_spec_special_agent_mail_domain_health = SpecialAgent(
    name="mail_domain_health",
    title=Title("Mail domain health"),
    topic=Topic.APPLICATIONS,
    parameter_form=_parameter_form,
)
