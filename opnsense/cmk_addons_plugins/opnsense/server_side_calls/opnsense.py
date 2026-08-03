#!/usr/bin/env python3
"""Server-side call: build the agent_opnsense command line from the ruleset."""
from collections.abc import Iterable
from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class OPNsenseParams(BaseModel):
    api_key: Secret
    api_secret: Secret
    port: int = 8443
    no_cert_check: bool = True
    timeout: int = 20


def _commands(params: OPNsenseParams, host_config: HostConfig
              ) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--api-key", params.api_key.unsafe(),
        "--api-secret", params.api_secret.unsafe(),
        "--port", str(params.port),
        "--timeout", str(params.timeout),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_opnsense = SpecialAgentConfig(
    name="opnsense",
    parameter_parser=OPNsenseParams.model_validate,
    commands_function=_commands,
)
