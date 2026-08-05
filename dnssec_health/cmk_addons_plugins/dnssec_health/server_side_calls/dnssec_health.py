#!/usr/bin/env python3
# Copyright (C) 2026 - License: GNU General Public License v2
"""Command line builder for the 'dnssec_health' special agent."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, SpecialAgentCommand, SpecialAgentConfig


class Params(BaseModel):
    domains: list[str] = []
    nameservers: list[str] = []
    timeout: float = 5.0


def _commands_function(params: Params, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    args: list[str] = []
    for domain in params.domains:
        args += ["--domain", domain]
    for nameserver in params.nameservers:
        args += ["--nameserver", nameserver]
    args += ["--timeout", str(params.timeout)]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_dnssec_health = SpecialAgentConfig(
    name="dnssec_health",
    parameter_parser=Params.model_validate,
    commands_function=_commands_function,
)
