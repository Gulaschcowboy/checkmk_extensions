#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Check plugins for the 'mail_domain_health' special agent.

Sections (JSON, one object per line):
  mail_domain_health_spf   -> service "SPF <domain>"
  mail_domain_health_dmarc -> service "DMARC <domain>"
  mail_domain_health_rbl   -> service "RBL <ip>"
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    State,
    check_levels,
    get_value_store,
)

Section = Mapping[str, Mapping[str, Any]]


def _parse_json_lines(string_table: list[list[str]], key: str) -> Section:
    section: dict[str, Mapping[str, Any]] = {}
    for line in string_table:
        if not line or not line[0].strip():
            continue
        try:
            data = json.loads(line[0])
        except ValueError:
            continue
        item = data.get(key)
        if isinstance(item, str):
            section[item] = data
    return section


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------


def parse_mail_domain_health_spf(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_spf = AgentSection(
    name="mail_domain_health_spf",
    parse_function=parse_mail_domain_health_spf,
)


def discover_mail_domain_health_spf(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


_KNOWN_SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
_KNOWN_SPF_MODIFIERS = {"redirect", "exp"}


def _spf_syntax_problems(record: str) -> list[str]:
    problems = []
    for term in record.split()[1:]:
        lowered = term.lower()
        if "=" in lowered.split(":", 1)[0]:
            modifier = lowered.split("=", 1)[0]
            if modifier not in _KNOWN_SPF_MODIFIERS and not re.match(r"^[a-z][a-z0-9_.-]*$", modifier):
                problems.append(f"malformed modifier {term!r}")
            continue
        mechanism = lowered.lstrip("+-~?").split(":", 1)[0].split("/", 1)[0]
        if mechanism not in _KNOWN_SPF_MECHANISMS:
            problems.append(f"unknown mechanism {term!r}")
    return problems


def _spf_all_qualifier(record: str) -> str | None:
    """Return '+', '-', '~', '?' or None if no 'all' mechanism is present."""
    for term in record.split()[1:]:
        stripped = term.lower().lstrip("+-~?")
        if stripped == "all":
            return term[0] if term[0] in "+-~?" else "+"
    return None


def check_mail_domain_health_spf(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    if data.get("error"):
        yield Result(state=State.UNKNOWN, summary=f"Query problem: {data['error']}")
        return

    records = data.get("spf_records") or []
    if not records:
        yield Result(state=State(params["state_no_record"]), summary="No SPF record published")
        return
    if len(records) > 1:
        yield Result(
            state=State(params["state_multiple_records"]),
            summary=f"{len(records)} SPF records published (RFC violation, SPF evaluates to permerror)",
        )
        for record in records:
            yield Result(state=State.OK, notice=f"Record: {record}")
        return

    record = records[0]
    yield Result(state=State.OK, summary=f"Record: {record}")

    # 'all' qualifier policy
    qualifier = _spf_all_qualifier(record)
    accepted = {
        "fail_only": ("-",),
        "softfail_or_fail": ("-", "~"),
        "any": ("-", "~", "?", "+"),
    }[params["allowed_all_qualifiers"]]
    if qualifier is None:
        yield Result(
            state=State(params["state_bad_all"]),
            summary="No 'all' mechanism (record does not terminate explicitly)",
        )
    elif qualifier not in accepted:
        yield Result(
            state=State(params["state_bad_all"]),
            summary=f"'{qualifier}all' does not match required policy",
        )
    else:
        yield Result(state=State.OK, summary=f"Terminates with '{qualifier}all'")

    # 10-lookup limit
    if (lookup_count := data.get("lookup_count")) is not None:
        yield from check_levels(
            float(lookup_count),
            levels_upper=params.get("lookup_levels"),
            metric_name="spf_dns_lookups",
            render_func=lambda v: str(int(v)),
            label="DNS lookups",
            boundaries=(0, None),
        )

    for problem in data.get("problems") or []:
        yield Result(state=State(params["state_record_problems"]), summary=problem)

    for syntax_problem in _spf_syntax_problems(record):
        yield Result(state=State(params["state_record_problems"]), summary=syntax_problem)

    if expected := params.get("expected_record"):
        if record.strip() != expected.strip():
            yield Result(
                state=State(params["state_record_mismatch"]),
                summary="Record differs from expected record",
                details=f"Expected: {expected}",
            )
        else:
            yield Result(state=State.OK, notice="Record matches expected record")


check_plugin_mail_domain_health_spf = CheckPlugin(
    name="mail_domain_health_spf",
    service_name="SPF %s",
    discovery_function=discover_mail_domain_health_spf,
    check_function=check_mail_domain_health_spf,
    check_ruleset_name="mail_domain_health_spf",
    check_default_parameters={
        "state_no_record": 2,
        "state_multiple_records": 2,
        "state_bad_all": 1,
        "state_record_problems": 1,
        "state_record_mismatch": 1,
        "allowed_all_qualifiers": "softfail_or_fail",
        "lookup_levels": ("fixed", (10, 11)),
    },
)


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------


def parse_mail_domain_health_dmarc(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_dmarc = AgentSection(
    name="mail_domain_health_dmarc",
    parse_function=parse_mail_domain_health_dmarc,
)


def discover_mail_domain_health_dmarc(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


_POLICY_RANK = {"none": 0, "quarantine": 1, "reject": 2}


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def check_mail_domain_health_dmarc(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    if data.get("error"):
        yield Result(state=State.UNKNOWN, summary=f"Query problem: {data['error']}")
        return

    records = data.get("dmarc_records") or []
    if not records:
        yield Result(state=State(params["state_no_record"]), summary="No DMARC record published")
        return
    if len(records) > 1:
        yield Result(
            state=State(params["state_multiple_records"]),
            summary=f"{len(records)} DMARC records published (receivers must ignore DMARC entirely)",
        )
        for record in records:
            yield Result(state=State.OK, notice=f"Record: {record}")
        return

    record = records[0]
    yield Result(state=State.OK, summary=f"Record: {record}")

    tags = _parse_dmarc_tags(record)
    policy = tags.get("p", "").lower()
    minimum = params["min_policy"]
    if policy not in _POLICY_RANK:
        yield Result(
            state=State(params["state_weak_policy"]),
            summary=f"Invalid or missing policy tag (p={policy or '<missing>'})",
        )
    elif _POLICY_RANK[policy] < _POLICY_RANK[minimum]:
        yield Result(
            state=State(params["state_weak_policy"]),
            summary=f"Policy p={policy} is weaker than required minimum ({minimum})",
        )
    else:
        yield Result(state=State.OK, summary=f"Policy: p={policy}")

    if (sub_policy := tags.get("sp", "").lower()) and sub_policy in _POLICY_RANK:
        if _POLICY_RANK[sub_policy] < _POLICY_RANK[minimum]:
            yield Result(
                state=State(params["state_weak_policy"]),
                summary=f"Subdomain policy sp={sub_policy} is weaker than required minimum ({minimum})",
            )
        else:
            yield Result(state=State.OK, notice=f"Subdomain policy: sp={sub_policy}")

    if params["require_rua"] and not tags.get("rua"):
        yield Result(
            state=State(params["state_no_rua"]),
            summary="No aggregate report address (rua=) configured",
        )
    elif tags.get("rua"):
        yield Result(state=State.OK, notice=f"Aggregate reports: {tags['rua']}")

    if (pct := tags.get("pct")) and pct.isdigit() and int(pct) < 100:
        yield Result(
            state=State(params["state_weak_policy"]),
            summary=f"Policy only applies to {pct}% of messages (pct={pct})",
        )


check_plugin_mail_domain_health_dmarc = CheckPlugin(
    name="mail_domain_health_dmarc",
    service_name="DMARC %s",
    discovery_function=discover_mail_domain_health_dmarc,
    check_function=check_mail_domain_health_dmarc,
    check_ruleset_name="mail_domain_health_dmarc",
    check_default_parameters={
        "state_no_record": 2,
        "state_multiple_records": 2,
        "state_weak_policy": 1,
        "state_no_rua": 1,
        "min_policy": "quarantine",
        "require_rua": True,
    },
)


# ---------------------------------------------------------------------------
# RBL
# ---------------------------------------------------------------------------


def parse_mail_domain_health_rbl(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "target")


agent_section_mail_domain_health_rbl = AgentSection(
    name="mail_domain_health_rbl",
    parse_function=parse_mail_domain_health_rbl,
)


def discover_mail_domain_health_rbl(section: Section) -> DiscoveryResult:
    for target in section:
        yield Service(item=target)


def check_mail_domain_health_rbl(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    if origin := data.get("origin"):
        yield Result(state=State.OK, notice=f"Source: {origin}")

    addresses = data.get("addresses") or []
    if not addresses:
        yield Result(
            state=State(params["state_unresolved"]),
            summary="Name does not resolve to any IP address",
        )
        return

    # Aggregate all listings/errors across every IP the target resolves to.
    all_listed: list[tuple[str, dict]] = []
    all_troubled: list[tuple[str, dict]] = []
    fcrdns_failures: list[str] = []
    total_queries = 0
    total_clean = 0

    ip_summaries: list[str] = []
    for address in addresses:
        ip = address.get("ip", "?")
        ptr = address.get("ptr")
        results = address.get("results") or []
        listed = [r for r in results if r.get("status") == "listed"]
        not_listed = [r for r in results if r.get("status") == "not_listed"]
        troubled = [r for r in results if r.get("status") in ("timeout", "error", "blocked")]
        total_queries += len(results)
        total_clean += len(not_listed)
        all_listed += [(ip, r) for r in listed]
        all_troubled += [(ip, r) for r in troubled]

        label = f"{ip} ({ptr})" if ptr else ip
        if listed:
            ip_summaries.append(f"{label}: listed on {', '.join(r['rbl'] for r in listed)}")
        else:
            ip_summaries.append(f"{label}: clean")

        # Per-IP detail block (shown in the service details). Every tested
        # DNSBL is listed with its individual finding, preserving the order in
        # which they were queried.
        detail_lines = [f"{label} - PTR: {ptr or 'none'}"]

        # Forward-confirmed reverse DNS (only present when the feature is enabled).
        fcrdns = address.get("fcrdns")
        if fcrdns is not None:
            status = fcrdns.get("status")
            forward = ", ".join(fcrdns.get("forward_ips") or []) or "none"
            if status == "pass":
                detail_lines.append(f"  [FCrDNS ok] {ptr} -> {forward}")
            elif status == "no_ptr":
                detail_lines.append("  [FCrDNS n/a] no PTR record")
                fcrdns_failures.append(f"{ip}: no PTR record")
            elif status == "no_forward":
                detail_lines.append(f"  [FCrDNS FAIL] PTR {ptr} does not resolve")
                fcrdns_failures.append(f"{ip}: PTR {ptr} does not resolve")
            else:  # fail
                detail_lines.append(
                    f"  [FCrDNS FAIL] PTR {ptr} resolves to {forward}, not {ip}"
                )
                fcrdns_failures.append(f"{ip}: PTR {ptr} -> {forward}")

        for entry in results:
            status = entry.get("status")
            rbl = entry.get("rbl", "?")
            if status == "listed":
                line = f"  [LISTED] {rbl}: codes {', '.join(entry.get('codes') or [])}"
                if entry.get("txt"):
                    line += f" - {entry['txt']}"
            elif status == "not_listed":
                line = f"  [clean]  {rbl}"
            elif status == "blocked":
                line = f"  [BLOCKED] {rbl}: {entry.get('txt') or 'query refused'}"
            elif status == "timeout":
                line = f"  [TIMEOUT] {rbl}: {entry.get('txt') or 'no response'}"
            else:  # error
                line = f"  [ERROR] {rbl}: {entry.get('txt') or 'query error'}"
            detail_lines.append(line)
        yield Result(state=State.OK, notice="\n".join(detail_lines))

    yield from check_levels(
        float(len(all_listed)),
        levels_upper=params.get("listed_levels"),
        metric_name="rbl_listings",
        render_func=lambda v: str(int(v)),
        label="Listed",
        boundaries=(0, float(total_queries) if total_queries else None),
    )

    ip_count = len(addresses)
    yield Result(
        state=State.OK,
        summary=f"{ip_count} IP{'s' if ip_count != 1 else ''}: " + "; ".join(ip_summaries),
    )

    yield Result(
        state=State.OK,
        summary=f"{total_clean}/{total_queries} lists clean",
    )

    if fcrdns_failures:
        yield Result(
            state=State(params["state_fcrdns_fail"]),
            summary=f"FCrDNS problem on {len(fcrdns_failures)} IP(s): {'; '.join(fcrdns_failures)}",
        )

    yield from check_levels(
        float(len(all_troubled)),
        levels_upper=params.get("error_levels"),
        metric_name="rbl_query_errors",
        render_func=lambda v: str(int(v)),
        label="Queries failed",
        notice_only=True,
    )


check_plugin_mail_domain_health_rbl = CheckPlugin(
    name="mail_domain_health_rbl",
    service_name="RBL %s",
    discovery_function=discover_mail_domain_health_rbl,
    check_function=check_mail_domain_health_rbl,
    check_ruleset_name="mail_domain_health_rbl",
    check_default_parameters={
        "listed_levels": ("fixed", (1, 2)),
        "error_levels": ("no_levels", None),
        "state_unresolved": 1,
        "state_fcrdns_fail": 1,
    },
)

# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------


def parse_mail_domain_health_dkim(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_dkim = AgentSection(
    name="mail_domain_health_dkim",
    parse_function=parse_mail_domain_health_dkim,
)


def discover_mail_domain_health_dkim(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_dkim(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    selectors = data.get("selectors") or {}
    found = {sel: info for sel, info in selectors.items() if info.get("found")}
    min_bits = params["min_key_bits"]

    if params["require_any_selector"] and not found:
        yield Result(
            state=State(params["state_no_selector"]),
            summary="None of the configured DKIM selectors were found",
        )

    if found:
        yield Result(
            state=State.OK,
            summary=f"{len(found)} of {len(selectors)} configured selectors present",
        )

    for selector, info in selectors.items():
        if not info.get("found"):
            if info.get("error"):
                yield Result(
                    state=State.OK, notice=f"{selector}: query problem - {info['error']}"
                )
            else:
                yield Result(state=State.OK, notice=f"{selector}: no record")
            continue

        if info.get("error"):
            yield Result(
                state=State(params["state_invalid"]),
                summary=f"{selector}: {info['error']}",
            )
            continue

        if info.get("revoked"):
            yield Result(
                state=State(params["state_revoked"]),
                summary=f"{selector}: key revoked (empty p=)",
            )
            continue

        if info.get("testing"):
            yield Result(
                state=State(params["state_testing"]),
                summary=f"{selector}: in test mode (t=y)",
            )

        key_type = info.get("key_type", "rsa")
        bits = info.get("key_bits")
        if key_type == "rsa" and bits is not None:
            if bits < min_bits:
                yield Result(
                    state=State(params["state_weak_key"]),
                    summary=f"{selector}: RSA key only {bits} bits (minimum {min_bits})",
                )
            else:
                yield Result(state=State.OK, notice=f"{selector}: RSA {bits} bits, valid")
        elif key_type == "ed25519":
            yield Result(state=State.OK, notice=f"{selector}: Ed25519 key, valid")
        else:
            yield Result(state=State.OK, notice=f"{selector}: {key_type} key present")


check_plugin_mail_domain_health_dkim = CheckPlugin(
    name="mail_domain_health_dkim",
    service_name="DKIM %s",
    discovery_function=discover_mail_domain_health_dkim,
    check_function=check_mail_domain_health_dkim,
    check_ruleset_name="mail_domain_health_dkim",
    check_default_parameters={
        "require_any_selector": True,
        "state_no_selector": 1,
        "state_invalid": 2,
        "state_revoked": 1,
        "state_testing": 1,
        "state_weak_key": 1,
        "min_key_bits": 2048,
    },
)


# ---------------------------------------------------------------------------
# Domain-based blacklists (DBL / SURBL / URIBL)
# ---------------------------------------------------------------------------


def parse_mail_domain_health_domain_bl(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_domain_bl = AgentSection(
    name="mail_domain_health_domain_bl",
    parse_function=parse_mail_domain_health_domain_bl,
)


def discover_mail_domain_health_domain_bl(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_domain_bl(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    results = data.get("results") or []
    listed = [r for r in results if r.get("status") == "listed"]
    not_listed = [r for r in results if r.get("status") == "not_listed"]
    troubled = [r for r in results if r.get("status") in ("timeout", "error", "blocked")]

    yield from check_levels(
        float(len(listed)),
        levels_upper=params.get("listed_levels"),
        metric_name="domain_bl_listings",
        render_func=lambda v: str(int(v)),
        label="Listed",
        boundaries=(0, float(len(results)) if results else None),
    )

    if listed:
        yield Result(
            state=State.OK,
            summary=f"Listed on: {', '.join(r['rbl'] for r in listed)}",
        )
    yield Result(state=State.OK, summary=f"{len(not_listed)}/{len(results)} lists clean")

    # Per-list details.
    for entry in results:
        status = entry.get("status")
        zone = entry.get("rbl", "?")
        if status == "listed":
            line = f"[LISTED] {zone}: codes {', '.join(entry.get('codes') or [])}"
            if entry.get("txt"):
                line += f" - {entry['txt']}"
        elif status == "not_listed":
            line = f"[clean]  {zone}"
        elif status == "blocked":
            line = f"[BLOCKED] {zone}: {entry.get('txt') or 'query refused'}"
        elif status == "timeout":
            line = f"[TIMEOUT] {zone}: {entry.get('txt') or 'no response'}"
        else:
            line = f"[ERROR] {zone}: {entry.get('txt') or 'query error'}"
        yield Result(state=State.OK, notice=line)

    yield from check_levels(
        float(len(troubled)),
        levels_upper=params.get("error_levels"),
        metric_name="domain_bl_query_errors",
        render_func=lambda v: str(int(v)),
        label="Queries failed",
        notice_only=True,
    )


check_plugin_mail_domain_health_domain_bl = CheckPlugin(
    name="mail_domain_health_domain_bl",
    service_name="Domain blacklist %s",
    discovery_function=discover_mail_domain_health_domain_bl,
    check_function=check_mail_domain_health_domain_bl,
    check_ruleset_name="mail_domain_health_domain_bl",
    check_default_parameters={
        "listed_levels": ("fixed", (1, 2)),
        "error_levels": ("no_levels", None),
    },
)


# ---------------------------------------------------------------------------
# MTA-STS + TLS-RPT
# ---------------------------------------------------------------------------


def parse_mail_domain_health_mta_sts(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


def _mx_matches_policy(host: str, patterns: list[str]) -> bool:
    """MTA-STS policy mx entries may be exact names or a single-label wildcard."""
    host = host.rstrip(".").lower()
    for pattern in patterns:
        pat = pattern.rstrip(".").lower()
        if pat.startswith("*."):
            suffix = pat[1:]  # ".example.com"
            # a wildcard matches exactly one label to the left of the suffix
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0 and host != suffix[1:]:
                return True
        elif host == pat:
            return True
    return False


agent_section_mail_domain_health_mta_sts = AgentSection(
    name="mail_domain_health_mta_sts",
    parse_function=parse_mail_domain_health_mta_sts,
)


def discover_mail_domain_health_mta_sts(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_mta_sts(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    sts = data.get("sts") or {}
    policy = data.get("policy")
    tls_rpt = data.get("tls_rpt") or {}

    # --- MTA-STS TXT record ---
    if sts.get("error"):
        yield Result(state=State.UNKNOWN, summary=f"MTA-STS query problem: {sts['error']}")
    elif not sts.get("found"):
        yield Result(
            state=State(params["state_no_sts"]),
            summary="No MTA-STS record published (_mta-sts TXT missing)",
        )
    else:
        current_id = sts.get("id")
        yield Result(state=State.OK, summary=f"MTA-STS record present (id={current_id})")

        # Detect policy id changes across check cycles (stateful).
        value_store = get_value_store()
        previous_id = value_store.get("mta_sts_id")
        if current_id is not None:
            value_store["mta_sts_id"] = current_id
        if previous_id is not None and current_id is not None and previous_id != current_id:
            yield Result(
                state=State(params["state_id_changed"]),
                summary=f"Policy id changed since last check ({previous_id} -> {current_id})",
            )

        # --- policy file (only fetched when the TXT record exists) ---
        if policy is None or not policy.get("fetched"):
            reason = (policy or {}).get("error") or "not fetched"
            yield Result(
                state=State(params["state_policy_error"]),
                summary=f"MTA-STS policy file could not be retrieved: {reason}",
            )
        else:
            mode = (policy.get("mode") or "").lower()
            mx_list = policy.get("mx") or []
            yield Result(
                state=State.OK,
                notice=f"Policy: mode={mode or '?'}, max_age={policy.get('max_age')}, "
                f"mx={', '.join(mx_list) or 'none'}",
            )
            if mode == "enforce":
                yield Result(state=State.OK, summary="Policy mode: enforce")
            elif mode in ("testing", "none"):
                yield Result(
                    state=State(params["state_not_enforcing"]),
                    summary=f"Policy mode: {mode} (not enforcing)",
                )
            else:
                yield Result(
                    state=State(params["state_policy_error"]),
                    summary=f"Policy mode invalid: {mode or 'missing'}",
                )
            if not mx_list:
                yield Result(
                    state=State(params["state_policy_error"]),
                    summary="Policy lists no mx hosts",
                )
            else:
                # Compare the policy mx patterns against the domain's actual MX hosts.
                actual_mx = data.get("actual_mx") or []
                if actual_mx and params.get("check_mx_match", True):
                    unmatched = [
                        host for host in actual_mx if not _mx_matches_policy(host, mx_list)
                    ]
                    if unmatched:
                        yield Result(
                            state=State(params["state_mx_mismatch"]),
                            summary=f"MX host(s) not covered by the policy: {', '.join(unmatched)}",
                        )
                    else:
                        yield Result(
                            state=State.OK,
                            notice=f"All {len(actual_mx)} MX host(s) covered by the policy",
                        )

            # max_age minimum: a short cache window weakens MTA-STS protection.
            min_max_age = params.get("min_max_age")
            raw_max_age = policy.get("max_age")
            if min_max_age is not None and raw_max_age is not None:
                try:
                    max_age_val = int(raw_max_age)
                except (TypeError, ValueError):
                    yield Result(
                        state=State(params["state_policy_error"]),
                        summary=f"Policy max_age is not an integer: {raw_max_age}",
                    )
                else:
                    if max_age_val < min_max_age:
                        yield Result(
                            state=State(params["state_short_max_age"]),
                            summary=f"Policy max_age {max_age_val}s is below the "
                            f"configured minimum of {min_max_age}s",
                        )

    # --- TLS-RPT record ---
    if tls_rpt.get("found"):
        yield Result(state=State.OK, notice=f"TLS-RPT present: rua={tls_rpt.get('rua')}")
    elif params["require_tls_rpt"]:
        yield Result(
            state=State(params["state_no_tls_rpt"]),
            summary="No TLS-RPT record published (_smtp._tls TXT missing)",
        )


check_plugin_mail_domain_health_mta_sts = CheckPlugin(
    name="mail_domain_health_mta_sts",
    service_name="MTA-STS %s",
    discovery_function=discover_mail_domain_health_mta_sts,
    check_function=check_mail_domain_health_mta_sts,
    check_ruleset_name="mail_domain_health_mta_sts",
    check_default_parameters={
        "state_no_sts": 1,
        "state_policy_error": 2,
        "state_not_enforcing": 0,
        "require_tls_rpt": True,
        "state_no_tls_rpt": 1,
        "check_mx_match": True,
        "state_mx_mismatch": 1,
        "state_id_changed": 0,
        "min_max_age": 604800,
        "state_short_max_age": 1,
    },
)


# ---------------------------------------------------------------------------
# DANE / TLSA
# ---------------------------------------------------------------------------

_TLSA_USAGE = {0: "PKIX-TA", 1: "PKIX-EE", 2: "DANE-TA", 3: "DANE-EE"}
_TLSA_SELECTOR = {0: "full-cert", 1: "SPKI"}
_TLSA_MATCHING = {0: "exact", 1: "SHA-256", 2: "SHA-512"}


def parse_mail_domain_health_dane(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_dane = AgentSection(
    name="mail_domain_health_dane",
    parse_function=parse_mail_domain_health_dane,
)


def discover_mail_domain_health_dane(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_dane(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    hosts = data.get("hosts") or []
    if not hosts:
        yield Result(state=State.OK, summary="No MX hosts to check")
        return

    hosts_with_tlsa = 0
    for host in hosts:
        name = host.get("host", "?")
        if host.get("error"):
            yield Result(state=State.OK, notice=f"{name}: query problem - {host['error']}")
            continue
        records = host.get("records") or []
        if not records:
            yield Result(
                state=State(params["state_no_tlsa"]),
                summary=f"{name}: no TLSA record published",
            )
            continue

        hosts_with_tlsa += 1
        # DANE is only meaningful when the TLSA records are DNSSEC-signed.
        if params["require_dnssec"] and not host.get("authenticated"):
            yield Result(
                state=State(params["state_not_signed"]),
                summary=f"{name}: TLSA present but not DNSSEC-validated (AD bit unset)",
            )

        for rec in records:
            usage = _TLSA_USAGE.get(rec["usage"], str(rec["usage"]))
            selector = _TLSA_SELECTOR.get(rec["selector"], str(rec["selector"]))
            matching = _TLSA_MATCHING.get(rec["matching"], str(rec["matching"]))
            yield Result(
                state=State.OK,
                notice=f"{name}: TLSA {usage} / {selector} / {matching}",
            )

        verified = host.get("verified")
        if verified == "match":
            yield Result(state=State.OK, summary=f"{name}: certificate matches TLSA")
        elif verified == "mismatch":
            yield Result(
                state=State(params["state_mismatch"]),
                summary=f"{name}: certificate does NOT match any TLSA record",
            )
        elif verified == "no_cert":
            yield Result(
                state=State(params["state_no_cert"]),
                summary=f"{name}: could not retrieve certificate via STARTTLS",
            )

    if hosts_with_tlsa:
        yield Result(
            state=State.OK,
            summary=f"{hosts_with_tlsa}/{len(hosts)} MX host(s) publish TLSA",
        )


check_plugin_mail_domain_health_dane = CheckPlugin(
    name="mail_domain_health_dane",
    service_name="DANE %s",
    discovery_function=discover_mail_domain_health_dane,
    check_function=check_mail_domain_health_dane,
    check_ruleset_name="mail_domain_health_dane",
    check_default_parameters={
        "state_no_tlsa": 1,
        "require_dnssec": True,
        "state_not_signed": 2,
        "state_mismatch": 2,
        "state_no_cert": 1,
    },
)


# ---------------------------------------------------------------------------
# BIMI
# ---------------------------------------------------------------------------


def parse_mail_domain_health_bimi(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_bimi = AgentSection(
    name="mail_domain_health_bimi",
    parse_function=parse_mail_domain_health_bimi,
)


def discover_mail_domain_health_bimi(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_bimi(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    if (data := section.get(item)) is None:
        return

    if data.get("error") and not data.get("found"):
        yield Result(state=State.UNKNOWN, summary=f"Query problem: {data['error']}")
        return

    if not data.get("found"):
        yield Result(
            state=State(params["state_no_record"]),
            summary="No BIMI record published",
        )
        return

    yield Result(state=State.OK, summary="BIMI record present")

    if data.get("logo_url"):
        yield Result(state=State.OK, notice=f"Logo (l=): {data['logo_url']}")
        logo_check = data.get("logo_check")
        if logo_check is not None:
            if not logo_check.get("reachable"):
                yield Result(
                    state=State(params["state_logo_unreachable"]),
                    summary=f"Logo URL not reachable: {logo_check.get('error')}",
                )
            elif not logo_check.get("is_svg"):
                yield Result(
                    state=State(params["state_logo_not_svg"]),
                    summary=f"Logo URL is reachable but not SVG "
                    f"(Content-Type: {logo_check.get('content_type')})",
                )
            else:
                yield Result(state=State.OK, notice="Logo URL reachable and is SVG")
    else:
        yield Result(
            state=State(params["state_no_logo"]),
            summary="BIMI record has no logo URL (l=)",
        )

    if data.get("vmc_url"):
        yield Result(state=State.OK, notice=f"VMC (a=): {data['vmc_url']}")
        vmc_check = data.get("vmc_check")
        if vmc_check is not None:
            if not vmc_check.get("reachable"):
                yield Result(
                    state=State(params["state_vmc_unreachable"]),
                    summary=f"VMC URL not reachable: {vmc_check.get('error')}",
                )
            else:
                yield Result(state=State.OK, notice="VMC URL reachable")
    elif params["require_vmc"]:
        yield Result(
            state=State(params["state_no_vmc"]),
            summary="BIMI record has no VMC certificate URL (a=)",
        )


check_plugin_mail_domain_health_bimi = CheckPlugin(
    name="mail_domain_health_bimi",
    service_name="BIMI %s",
    discovery_function=discover_mail_domain_health_bimi,
    check_function=check_mail_domain_health_bimi,
    check_ruleset_name="mail_domain_health_bimi",
    check_default_parameters={
        "state_no_record": 1,
        "state_no_logo": 2,
        "require_vmc": False,
        "state_no_vmc": 1,
        "state_logo_unreachable": 1,
        "state_logo_not_svg": 1,
        "state_vmc_unreachable": 1,
    },
)


# ---------------------------------------------------------------------------
# Domain registration expiry (RDAP)
# ---------------------------------------------------------------------------


def parse_mail_domain_health_rdap(string_table: list[list[str]]) -> Section:
    return _parse_json_lines(string_table, "domain")


agent_section_mail_domain_health_rdap = AgentSection(
    name="mail_domain_health_rdap",
    parse_function=parse_mail_domain_health_rdap,
)


def discover_mail_domain_health_rdap(section: Section) -> DiscoveryResult:
    for domain in section:
        yield Service(item=domain)


def check_mail_domain_health_rdap(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    import datetime

    if (data := section.get(item)) is None:
        return

    expiry = data.get("expiry")
    if not expiry:
        yield Result(
            state=State.UNKNOWN,
            summary=f"Expiry date unavailable: {data.get('error') or 'unknown'}",
        )
        return

    if data.get("registrar"):
        yield Result(state=State.OK, notice=f"Registrar: {data['registrar']}")

    try:
        expiry_dt = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except ValueError:
        yield Result(state=State.UNKNOWN, summary=f"Unparseable expiry date: {expiry}")
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = int((expiry_dt - now).total_seconds() // 86400)

    yield from check_levels(
        days_left,
        levels_lower=params.get("age_levels"),
        metric_name="domain_expiry_days",
        render_func=lambda v: f"{int(v)} days",
        label="Expires in",
        boundaries=(0, None),
    )
    yield Result(
        state=State.OK,
        notice=f"Expiration date: {expiry_dt.date().isoformat()}",
    )


check_plugin_mail_domain_health_rdap = CheckPlugin(
    name="mail_domain_health_rdap",
    service_name="Domain expiry %s",
    discovery_function=discover_mail_domain_health_rdap,
    check_function=check_mail_domain_health_rdap,
    check_ruleset_name="mail_domain_health_rdap",
    check_default_parameters={
        "age_levels": ("fixed", (30, 14)),
    },
)
