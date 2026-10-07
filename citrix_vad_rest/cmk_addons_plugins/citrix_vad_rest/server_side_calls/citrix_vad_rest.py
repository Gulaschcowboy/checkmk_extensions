#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Server-side call: build the agent_citrix_vad_rest command line from the ruleset."""
from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)


class CitrixVadRestParams(BaseModel):
    ddc_address: str | None = None
    port: int = 443
    user: str
    password: Secret
    no_cert_check: bool = True
    timeout: int = 20
    max_machines: int = 2000
    max_sessions: int = 10000
    strip_domain_suffix: str = ""
    no_hostsystem: bool = False


def _commands(params: CitrixVadRestParams, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    ddc_address = params.ddc_address or host_config.primary_ip_config.address
    args: list = [
        "--ddc", ddc_address,
        "--port", str(params.port),
        "--user", params.user,
        "--password", params.password.unsafe(),
        "--timeout", str(params.timeout),
        "--max-machines", str(params.max_machines),
        "--max-sessions", str(params.max_sessions),
    ]
    if params.strip_domain_suffix:
        args += ["--strip-domain-suffix", params.strip_domain_suffix]
    if params.no_cert_check:
        args.append("--no-cert-check")
    if params.no_hostsystem:
        args.append("--no-hostsystem")
    yield SpecialAgentCommand(command_arguments=args)


special_agent_citrix_vad_rest = SpecialAgentConfig(
    name="citrix_vad_rest",
    parameter_parser=CitrixVadRestParams.model_validate,
    commands_function=_commands,
)
