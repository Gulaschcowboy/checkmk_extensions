#!/usr/bin/env python3
# Connects the GUI rule (special agent) with the program
# libexec/agent_monitoring_compliance.

from collections.abc import Iterator, Mapping

from cmk.server_side_calls.v1 import (
    HostConfig,
    SpecialAgentCommand,
    SpecialAgentConfig,
    noop_parser,
)


def _commands(
    params: Mapping[str, object],
    host_config: HostConfig,
) -> Iterator[SpecialAgentCommand]:
    args: list[str] = ["--hostname", host_config.name]

    cache_ttl = params.get("cache_ttl")
    if cache_ttl is not None:
        args += ["--cache-ttl", str(int(cache_ttl))]  # type: ignore[arg-type]
    if params.get("no_plugin_check"):
        args.append("--no-available")
    if params.get("no_labels"):
        args.append("--no-labels")
    if params.get("no_inventory"):
        args.append("--no-inventory")
    if params.get("report_db_stats"):
        args.append("--db-stats")
        db_path = params.get("db_path")
        if db_path:
            args += ["--db-path", str(db_path)]
    if params.get("report_known_catalog"):
        args.append("--known-catalog")
    socket_path = params.get("livestatus_socket")
    if socket_path:
        args += ["--livestatus-socket", str(socket_path)]

    yield SpecialAgentCommand(command_arguments=args)


special_agent_monitoring_compliance = SpecialAgentConfig(
    name="monitoring_compliance",
    parameter_parser=noop_parser,
    commands_function=_commands,
)
