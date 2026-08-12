#!/usr/bin/env python3
"""Server-side call: build the agent_hermes_dashboard command line from the ruleset."""
from collections.abc import Iterable
from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class HermesDashboardParams(BaseModel):
    port: int = 9119
    protocol: str = "http"
    username: str | None = None
    password: Secret | None = None
    timeout: int = 10
    fetch_usage: bool = False
    usage_days: int = 1
    no_cert_check: bool = False


def _commands(params: HermesDashboardParams, host_config: HostConfig
              ) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--port", str(params.port),
        "--protocol", params.protocol,
        "--timeout", str(params.timeout),
    ]
    if params.username:
        args += ["--username", params.username]
    if params.password is not None:
        args += ["--password", params.password.unsafe()]
    if params.fetch_usage:
        args += ["--fetch-usage", "--usage-days", str(params.usage_days)]
    if params.no_cert_check:
        args.append("--no-cert-check")
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_hermes_dashboard = SpecialAgentConfig(
    name="hermes_dashboard",
    parameter_parser=HermesDashboardParams.model_validate,
    commands_function=_commands,
)
