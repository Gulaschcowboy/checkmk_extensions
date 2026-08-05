#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Command line builder for the 'mail_domain_health' special agent."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, SpecialAgentCommand, SpecialAgentConfig


class DkimPerDomain(BaseModel):
    domain: str
    selectors: list[str] = []


class DkimConfig(BaseModel):
    selectors: list[str] = []
    per_domain: list[DkimPerDomain] = []


class DomainBlacklistConfig(BaseModel):
    zones: list[str] = []


class RblConfig(BaseModel):
    targets: list[str] = []
    resolve_mx: bool = False
    rbls: list[str] = []


class DaneConfig(BaseModel):
    verify_certificate: bool = False


class BimiConfig(BaseModel):
    selector: str = "default"
    check_reachability: bool = False


class Params(BaseModel):
    domains: list[str] = []
    spf: bool = True
    dmarc: bool = True
    rbl: RblConfig | None = None
    nameservers: list[str] = []
    timeout: float = 5.0
    dkim: DkimConfig | None = None
    domain_blacklists: DomainBlacklistConfig | None = None
    fcrdns: bool = False
    mta_sts: bool = False
    http_timeout: float = 10.0
    dane: DaneConfig | None = None
    bimi: BimiConfig | None = None
    rdap: bool = False


def _commands_function(
    params: Params, host_config: HostConfig
) -> Iterable[SpecialAgentCommand]:
    args: list[str] = []
    for domain in params.domains:
        args += ["--domain", domain]
    if not params.spf:
        args.append("--no-spf")
    if not params.dmarc:
        args.append("--no-dmarc")
    if params.rbl is not None:
        for target in params.rbl.targets:
            args += ["--target", target]
        for rbl in params.rbl.rbls:
            args += ["--rbl", rbl]
        if params.rbl.resolve_mx:
            args.append("--resolve-mx")
    for nameserver in params.nameservers:
        args += ["--nameserver", nameserver]
    if params.dkim is not None:
        for selector in params.dkim.selectors:
            args += ["--dkim-selector", selector]
        for entry in params.dkim.per_domain:
            for selector in entry.selectors:
                args += ["--dkim-selector-for", f"{entry.domain}={selector}"]
    if params.domain_blacklists is not None:
        args.append("--check-domain-bl")
        for zone in params.domain_blacklists.zones:
            args += ["--domain-bl", zone]
    if params.fcrdns:
        args.append("--fcrdns")
    if params.mta_sts:
        args.append("--mta-sts")
    if params.dane is not None:
        args.append("--dane")
        if params.dane.verify_certificate:
            args.append("--dane-verify")
    if params.bimi is not None:
        args.append("--bimi")
        if params.bimi.selector:
            args += ["--bimi-selector", params.bimi.selector]
        if params.bimi.check_reachability:
            args.append("--bimi-check-urls")
    if params.rdap:
        args.append("--rdap")
    if params.mta_sts or params.bimi is not None or params.rdap:
        args += ["--http-timeout", str(params.http_timeout)]
    args += ["--timeout", str(params.timeout)]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_mail_domain_health = SpecialAgentConfig(
    name="mail_domain_health",
    parameter_parser=Params.model_validate,
    commands_function=_commands_function,
)
