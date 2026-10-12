#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Server-side call: build the agent_linotp_rest command line from the ruleset."""
from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, Secret, SpecialAgentCommand, SpecialAgentConfig


class LinotpRestParams(BaseModel):
    url: str
    user: str
    password: Secret
    no_cert_check: bool = True
    timeout: int = 15


def _commands(params: LinotpRestParams, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--url", params.url,
        "--user", params.user,
        "--password", params.password.unsafe(),
        "--timeout", str(params.timeout),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    yield SpecialAgentCommand(command_arguments=args)


special_agent_linotp_rest = SpecialAgentConfig(
    name="linotp_rest",
    parameter_parser=LinotpRestParams.model_validate,
    commands_function=_commands,
)
