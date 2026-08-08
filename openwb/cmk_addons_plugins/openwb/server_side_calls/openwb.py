#!/usr/bin/env python3
"""Server-side call: build the agent_openwb command line from the ruleset."""
from collections.abc import Iterable
from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class OpenWBParams(BaseModel):
    port: int = 80
    https: bool = False
    no_cert_check: bool = True
    username: str | None = None
    password: Secret | None = None
    timeout: int = 20
    max_chargepoint_id: int = 9
    max_counter_id: int = 19
    max_battery_id: int = 19
    max_pv_id: int = 19


def _commands(params: OpenWBParams, host_config: HostConfig
              ) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--port", str(params.port),
        "--timeout", str(params.timeout),
        "--max-chargepoint-id", str(params.max_chargepoint_id),
        "--max-counter-id", str(params.max_counter_id),
        "--max-battery-id", str(params.max_battery_id),
        "--max-pv-id", str(params.max_pv_id),
    ]
    if params.https:
        args.append("--https")
        if params.no_cert_check:
            args.append("--no-cert-check")
    if params.username:
        args += ["--username", params.username]
    if params.password is not None:
        args += ["--password", params.password.unsafe()]
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_openwb = SpecialAgentConfig(
    name="openwb",
    parameter_parser=OpenWBParams.model_validate,
    commands_function=_commands,
)
