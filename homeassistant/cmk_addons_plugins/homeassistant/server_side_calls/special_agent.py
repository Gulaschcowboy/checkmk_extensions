#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from cmk.server_side_calls.v1 import SpecialAgentCommand, SpecialAgentConfig, noop_parser


def _agent_arguments(params, host_config):
    args = [
        "--url", str(params["url"]),
        "--token", params["token"].unsafe(),
        "--domains", str(params.get("domains", "sensor,binary_sensor")),
        "--host-prefix", str(params.get("host_prefix", "ha-")),
        "--timeout", str(params.get("timeout", 10.0)),
        "--stale-after", str(params.get("stale_after", 0.0)),
        "--max-hosts", str(int(params.get("max_hosts", 150))),
        "--max-entities", str(int(params.get("max_entities", 450))),
    ]
    include_regex = str(params.get("include_regex") or "")
    exclude_regex = str(params.get("exclude_regex") or "")
    if include_regex:
        args += ["--include-regex", include_regex]
    if exclude_regex:
        args += ["--exclude-regex", exclude_regex]
    if params.get("ignore_unavailable", False):
        args.append("--ignore-unavailable")
    if not params.get("verify_tls", True):
        args.append("--no-verify-tls")
    yield SpecialAgentCommand(command_arguments=args)


special_agent_homeassistant = SpecialAgentConfig(
    name="homeassistant",
    parameter_parser=noop_parser,
    commands_function=_agent_arguments,
)
