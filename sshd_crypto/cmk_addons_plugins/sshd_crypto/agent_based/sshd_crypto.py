#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Check plug-in "sshd_crypto": evaluates the algorithm lists offered by the
# OpenSSH daemon (sshd -T) -- post-quantum key exchange availability,
# disallowed (weak/legacy) and required algorithms per category.
#
# Note on SSH negotiation: the algorithm used for a connection is the first
# entry of the CLIENT's list that the server also supports. The order of the
# server's list is therefore irrelevant; only the set of offered algorithms
# matters. That is what this check evaluates.

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    StringTable,
)

# sshd -T option -> internal category key
_OPTION_TO_CATEGORY = {
    "kexalgorithms": "kex",
    "ciphers": "ciphers",
    "macs": "macs",
    "hostkeyalgorithms": "hostkey",
    "pubkeyacceptedalgorithms": "pubkey",
    "pubkeyacceptedkeytypes": "pubkey",  # OpenSSH < 8.5
}

_CATEGORY_TITLES = {
    "kex": "Key exchange algorithms",
    "ciphers": "Ciphers",
    "macs": "MACs",
    "hostkey": "Host key algorithms",
    "pubkey": "Accepted public key algorithms",
}

_CATEGORY_LABELS = {
    "kex": "key exchange algorithms",
    "ciphers": "ciphers",
    "macs": "MACs",
    "hostkey": "host key algorithms",
    "pubkey": "public key algorithms",
}

# Default parameters. Patterns are shell-style wildcards (fnmatch, case
# sensitive) matched against each single algorithm name.
DEFAULT_PARAMETERS: Mapping[str, Any] = {
    "pqc_algorithms": ["*mlkem*", "*sntrup*", "*kyber*"],
    "pqc_missing_state": 1,
    "classic_kex_state": 0,
    "forbidden_state": 1,
    "required_state": 1,
    # Only algorithms that are broken/deprecated and NOT part of any current
    # OpenSSH default set -- a stock modern sshd stays OK.
    "forbidden_kex": [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ],
    "forbidden_ciphers": ["*-cbc", "*cbc@*", "arcfour*", "3des*", "blowfish*", "cast128*"],
    "forbidden_macs": ["hmac-md5*", "hmac-sha1-96*", "hmac-ripemd160*"],
    "forbidden_hostkey": ["ssh-dss*", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com"],
    "forbidden_pubkey": ["ssh-dss*", "ssh-rsa", "ssh-rsa-cert-v01@openssh.com"],
}


@dataclass(frozen=True)
class SshdCrypto:
    version: str | None = None
    algorithms: Mapping[str, Sequence[str]] = field(default_factory=dict)


def parse_sshd_crypto(string_table: StringTable) -> SshdCrypto | None:
    version = None
    algorithms: dict[str, list[str]] = {}
    for line in string_table:
        if not line:
            continue
        key = line[0].lower()
        value = " ".join(line[1:]).strip()
        if key == "version":
            version = value or None
        elif (category := _OPTION_TO_CATEGORY.get(key)) is not None:
            algorithms[category] = [a for a in value.split(",") if a]
    if not algorithms:
        return None
    return SshdCrypto(version=version, algorithms=algorithms)


agent_section_sshd_crypto = AgentSection(
    name="sshd_crypto",
    parse_function=parse_sshd_crypto,
)


def discover_sshd_crypto(section: SshdCrypto) -> DiscoveryResult:
    if "kex" in section.algorithms:
        yield Service()


def _matching(algorithms: Sequence[str], patterns: Sequence[str]) -> list[str]:
    return [a for a in algorithms if any(fnmatchcase(a, p) for p in patterns)]


def _short_version(version: str) -> str:
    # "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024" -> "OpenSSH_9.6p1"
    return version.split()[0].rstrip(",")


def check_sshd_crypto(params: Mapping[str, Any], section: SshdCrypto) -> CheckResult:
    if section.version:
        yield Result(
            state=State.OK,
            summary=_short_version(section.version),
            details=f"Version: {section.version}",
        )

    # --- post-quantum key exchange -------------------------------------
    kex = section.algorithms.get("kex", [])
    pqc = _matching(kex, params["pqc_algorithms"])
    classic = [a for a in kex if a not in pqc]
    if pqc:
        yield Result(state=State.OK, summary=f"PQC key exchange: {', '.join(pqc)}")
        if classic:
            state = State(params["classic_kex_state"])
            text = f"Classic (non-PQC) key exchange still offered: {len(classic)}"
            if state is State.OK:
                yield Result(state=state, notice=text)
            else:
                yield Result(state=state, summary=text, details=f"{text} ({', '.join(classic)})")
    else:
        yield Result(
            state=State(params["pqc_missing_state"]),
            summary="No post-quantum (PQC) key exchange offered",
        )

    # --- disallowed algorithms per category -----------------------------
    forbidden_state = State(params["forbidden_state"])
    for category, label in _CATEGORY_LABELS.items():
        offered = section.algorithms.get(category)
        if offered is None:
            continue
        hits = _matching(offered, params.get(f"forbidden_{category}", []))
        if hits:
            yield Result(
                state=forbidden_state,
                summary=f"Disallowed {label} offered: {', '.join(hits)}",
            )

    # --- required algorithms per category -------------------------------
    # Every configured pattern must match at least one offered algorithm.
    required_state = State(params["required_state"])
    for category, label in _CATEGORY_LABELS.items():
        patterns = params.get(f"required_{category}", [])
        if not patterns:
            continue
        offered = section.algorithms.get(category, [])
        missing = [p for p in patterns if not any(fnmatchcase(a, p) for a in offered)]
        if missing:
            yield Result(
                state=required_state,
                summary=f"Required {label} not offered: {', '.join(missing)}",
            )

    # --- full lists (details only) ---------------------------------------
    for category, title in _CATEGORY_TITLES.items():
        offered = section.algorithms.get(category)
        if offered is not None:
            yield Result(state=State.OK, notice=f"{title}: {', '.join(offered) or '(none)'}")


check_plugin_sshd_crypto = CheckPlugin(
    name="sshd_crypto",
    service_name="SSH daemon crypto",
    discovery_function=discover_sshd_crypto,
    check_function=check_sshd_crypto,
    check_ruleset_name="sshd_crypto",
    check_default_parameters=DEFAULT_PARAMETERS,
)
