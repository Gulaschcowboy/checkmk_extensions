#!/usr/bin/env python3
"""Server-side call: build the agent_xenserver command line from the ruleset.

The password is passed as a password store reference (--password-id), the
core substitutes "<id>:<file>" and the agent decrypts it itself, so the secret
never shows up in the process list or the fetcher configuration.
"""
from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class XenParams(BaseModel):
    user: str
    password: Secret
    port: int = 443
    no_cert_check: bool = False
    timeout: int = 20
    pool_members: list[str] = []
    host_naming: str = "name_label"
    vm_naming: str = "name_label"
    alerts_hours: int = 24
    skip_vms: bool = False


def _commands(params: XenParams, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--user", params.user,
        "--port", str(params.port),
        "--timeout", str(params.timeout),
        "--hostname", host_config.name,
        "--host-naming", params.host_naming,
        "--vm-naming", params.vm_naming,
        "--alerts-hours", str(params.alerts_hours),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    if params.pool_members:
        args += ["--pool-members", ",".join(params.pool_members)]
    if params.skip_vms:
        args.append("--no-vms")
    args += ["--password-id", params.password]
    args.append(host_config.primary_ip_config.address)
    yield SpecialAgentCommand(command_arguments=args)


special_agent_xenserver = SpecialAgentConfig(
    name="xenserver",
    parameter_parser=XenParams.model_validate,
    commands_function=_commands,
)
