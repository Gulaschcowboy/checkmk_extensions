#!/usr/bin/env python3
"""Server-side call: build the agent_pmg command line from the ruleset."""
from collections.abc import Iterable
from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class PMGParams(BaseModel):
    username: str
    password: Secret
    realm: str = "pmg"
    port: int = 8006
    no_cert_check: bool = True
    timeout: int = 20
    quarantine_lookback_days: int = 30


def _commands(params: PMGParams, host_config: HostConfig
              ) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--username", params.username,
        "--password", params.password.unsafe(),
        "--realm", params.realm,
        "--port", str(params.port),
        "--timeout", str(params.timeout),
        "--quarantine-lookback-days", str(params.quarantine_lookback_days),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_pmg = SpecialAgentConfig(
    name="pmg",
    parameter_parser=PMGParams.model_validate,
    commands_function=_commands,
)
