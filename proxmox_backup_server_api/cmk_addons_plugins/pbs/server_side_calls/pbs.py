#!/usr/bin/env python3
"""Server-side call: build the agent_pbs command line from the ruleset."""
from collections.abc import Iterable
from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class PBSParams(BaseModel):
    token_id: str
    token_secret: Secret
    port: int = 8007
    node: str = "localhost"
    task_limit: int = 500
    no_cert_check: bool = True
    timeout: int = 20


def _commands(params: PBSParams, host_config: HostConfig
              ) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--token-id", params.token_id,
        "--token-secret", params.token_secret.unsafe(),
        "--port", str(params.port),
        "--node", params.node,
        "--task-limit", str(params.task_limit),
        "--timeout", str(params.timeout),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_pbs = SpecialAgentConfig(
    name="pbs",
    parameter_parser=PBSParams.model_validate,
    commands_function=_commands,
)
