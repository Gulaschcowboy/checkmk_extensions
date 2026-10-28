#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Check parameters for "SSH daemon crypto": which key exchange algorithms
# count as post-quantum, state if none is offered, and per-category lists
# of disallowed and required algorithm patterns.

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    List,
    ServiceState,
    String,
)
from cmk.rulesets.v1.form_specs.validators import LengthInRange
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic

_PATTERN_HELP = (
    "Shell-style wildcard patterns (<tt>*</tt>, <tt>?</tt>, <tt>[...]</tt>), "
    "matched case-sensitively against every single algorithm name the SSH "
    "daemon offers. "
)

_FORBIDDEN_DEFAULTS = {
    "kex": [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    "ciphers": ["*-cbc", "*cbc@*", "arcfour*", "3des*", "blowfish*", "cast128*"],
    "macs": ["hmac-md5*", "hmac-sha1-96*", "hmac-ripemd160*"],
    "hostkey": ["ssh-dss*", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com"],
    "pubkey": ["ssh-dss*", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com"],
}

_FORBIDDEN_TITLES = {
    "kex": "Disallowed key exchange algorithms (KexAlgorithms)",
    "ciphers": "Disallowed ciphers (Ciphers)",
    "macs": "Disallowed MACs (MACs)",
    "hostkey": "Disallowed host key algorithms (HostKeyAlgorithms)",
    "pubkey": "Disallowed public key algorithms (PubkeyAcceptedAlgorithms)",
}


_REQUIRED_TITLES = {
    "kex": "Required key exchange algorithms (KexAlgorithms)",
    "ciphers": "Required ciphers (Ciphers)",
    "macs": "Required MACs (MACs)",
    "hostkey": "Required host key algorithms (HostKeyAlgorithms)",
    "pubkey": "Required public key algorithms (PubkeyAcceptedAlgorithms)",
}


def _pattern_list(title: str, help_text: str, default: list[str]) -> List[str]:
    return List(
        title=Title(title),
        help_text=Help(
            help_text
            + (
                " If this option is not set, the default is: <tt>"
                + ", ".join(default)
                + "</tt>."
                if default
                else " Not checked if this option is not set."
            )
        ),
        element_template=String(custom_validate=(LengthInRange(min_value=1),)),
        editable_order=False,
    )


def _form_spec_sshd_crypto() -> Dictionary:
    elements: dict[str, DictElement] = {
        "pqc_algorithms": DictElement(
            parameter_form=_pattern_list(
                "Key exchange algorithms considered post-quantum (PQC)",
                _PATTERN_HELP
                + "A key exchange algorithm matching one of these patterns counts "
                "as post-quantum, e.g. <tt>mlkem768x25519-sha256</tt> or "
                "<tt>sntrup761x25519-sha512@openssh.com</tt>.",
                ["*mlkem*", "*sntrup*", "*kyber*"],
            ),
        ),
        "pqc_missing_state": DictElement(
            parameter_form=ServiceState(
                title=Title("State if no post-quantum key exchange is offered"),
                prefill=DefaultValue(ServiceState.WARN),
            ),
        ),
        "classic_kex_state": DictElement(
            parameter_form=ServiceState(
                title=Title("State if classic (non-PQC) key exchange is offered in addition"),
                help_text=Help(
                    "Applies only if at least one post-quantum key exchange is "
                    "offered. Clients without PQC support can still connect using a "
                    "classic algorithm. Set this to WARN/CRIT to enforce a PQC-only "
                    "key exchange configuration."
                ),
                prefill=DefaultValue(ServiceState.OK),
            ),
        ),
        "forbidden_state": DictElement(
            parameter_form=ServiceState(
                title=Title("State if a disallowed algorithm is offered"),
                prefill=DefaultValue(ServiceState.WARN),
            ),
        ),
        "required_state": DictElement(
            parameter_form=ServiceState(
                title=Title("State if a required algorithm is not offered"),
                prefill=DefaultValue(ServiceState.WARN),
            ),
        ),
    }
    for category, title in _FORBIDDEN_TITLES.items():
        elements[f"forbidden_{category}"] = DictElement(
            parameter_form=_pattern_list(
                title,
                _PATTERN_HELP
                + "If the daemon offers an algorithm matching one of these "
                "patterns, the service goes to the configured state. Use an empty "
                "list to disable the check for this category.",
                _FORBIDDEN_DEFAULTS[category],
            ),
        )
    for category, title in _REQUIRED_TITLES.items():
        elements[f"required_{category}"] = DictElement(
            parameter_form=_pattern_list(
                title,
                _PATTERN_HELP
                + "Every pattern must match at least one algorithm the daemon "
                "offers, otherwise the service goes to the configured state, "
                "e.g. <tt>ssh-ed25519</tt> or <tt>*-gcm@openssh.com</tt>.",
                [],
            ),
        )
    return Dictionary(
        help_text=Help(
            "Evaluates the algorithm lists the OpenSSH daemon offers according to "
            "its effective configuration (<tt>sshd -T</tt>), as reported by the "
            "agent plug-in <tt>sshd_crypto</tt>. Match blocks are not evaluated."
        ),
        elements=elements,
    )


rule_spec_sshd_crypto = CheckParameters(
    title=Title("SSH daemon crypto algorithms"),
    name="sshd_crypto",
    topic=Topic.APPLICATIONS,
    parameter_form=_form_spec_sshd_crypto,
    condition=HostCondition(),
)
