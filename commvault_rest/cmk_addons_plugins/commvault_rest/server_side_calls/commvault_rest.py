#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Server-side call: build the agent_commvault_rest command line from the ruleset.

The password is passed as a password store reference (--password-id); the agent
decrypts it itself, so the secret never shows up in the process list.
"""
from collections.abc import Iterable

from pydantic import BaseModel

from cmk.server_side_calls.v1 import HostConfig, Secret, SpecialAgentCommand, SpecialAgentConfig


class CommvaultRestParams(BaseModel):
    url: str
    user: str
    password: Secret
    no_cert_check: bool = False
    timeout: int = 60
    job_lookback: float = 7 * 86400.0
    page_size: int = 5000
    skip_ddp: bool = False
    sections: list[str] = ["jobs", "storage", "vms", "vm_piggyback", "mediaagents", "license"]


def _commands(params: CommvaultRestParams, host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    args: list = [
        "--url", params.url,
        "--user", params.user,
        "--timeout", str(params.timeout),
        "--job-lookback", str(int(params.job_lookback)),
        "--page-size", str(params.page_size),
    ]
    if params.no_cert_check:
        args.append("--no-cert-check")
    if params.skip_ddp:
        args.append("--skip-ddp")
    for name, flag in (("jobs", "--no-jobs"), ("storage", "--no-storage"), ("vms", "--no-vms"),
                       ("vm_piggyback", "--no-vm-piggyback"), ("mediaagents", "--no-mediaagents"),
                       ("license", "--no-license")):
        if name not in params.sections:
            args.append(flag)
    args += ["--password-id", params.password]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_commvault_rest = SpecialAgentConfig(
    name="commvault_rest",
    parameter_parser=CommvaultRestParams.model_validate,
    commands_function=_commands,
)
