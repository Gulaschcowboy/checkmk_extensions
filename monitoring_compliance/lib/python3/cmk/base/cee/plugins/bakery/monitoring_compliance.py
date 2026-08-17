#!/usr/bin/env python3
# Agent Bakery registration for the optional Monitoring Compliance agent
# plug-ins (Linux shell + Windows PowerShell). Commercial editions only.
#
# Uses the established bakery location (Libraries part). The agent plug-in
# source files are shipped in the "agents" part:
#   agents/plugins/mk_monitoring_compliance            (Linux)
#   agents/windows/plugins/mk_monitoring_compliance.ps1 (Windows)
# For OS.LINUX the source path is resolved under agents/plugins/, for
# OS.WINDOWS under agents/windows/plugins/.

from pathlib import Path

from cmk.base.plugins.bakery.bakery_api.v1 import OS, Plugin, register


def _get_files(conf):
    # conf is the AgentConfig rule value (a dict). Deploy only when requested.
    if not isinstance(conf, dict) or not conf.get("deploy"):
        return
    raw_interval = conf.get("interval")
    interval = int(raw_interval) if raw_interval else None

    yield Plugin(
        base_os=OS.LINUX,
        source=Path("mk_monitoring_compliance"),
        interval=interval,
    )
    yield Plugin(
        base_os=OS.WINDOWS,
        source=Path("mk_monitoring_compliance.ps1"),
        interval=interval,
    )


register.bakery_plugin(
    name="monitoring_compliance",
    files_function=_get_files,
)
