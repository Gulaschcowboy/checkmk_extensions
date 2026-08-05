#!/usr/bin/env python3
"""Agent Bakery plugin for the agent-based PowerDNS package.

Makes the ``powerdns`` agent plugin bakeable. It appears under
Setup -> Agents -> Windows/Linux Agent -> "Agent plugins" as the rule
"PowerDNS (agent-based)", deploying the agent plugin and, optionally, writing
/etc/check_mk/powerdns.cfg from the rule.

Note the division of labour: unlike the local-check variant, this package keeps
thresholds and zone-discovery filtering in the normal WATO check rulesets, so
this bakery rule only carries connection settings and record-counting options.

The Bakery API is a commercial-edition feature; on Raw this module is not
loaded.
"""

from pathlib import Path
from typing import Any

from .bakery_api.v1 import (
    OS,
    FileGenerator,
    Plugin,
    PluginConfig,
    password_store,
    register,
)


def _resolve_password(value: Any) -> str:
    """Turn a form_spec Password value into the plaintext secret.

    The ``Password`` form_spec (with ``migrate_to_password``) delivers a
    ``('cmk_postprocessed', 'explicit_password'|'stored_password', (id, secret))``
    tuple, not a bare string. Writing that tuple verbatim into powerdns.cfg is a
    bug: the agent plugin would send the whole repr as the ``X-API-Key`` header
    and the PowerDNS API answers 401. ``extract_formspec_password`` resolves both
    the explicit and the stored-password variants to the plaintext secret.
    Older rules (or a plain string) are passed through unchanged.
    """
    if isinstance(value, (tuple, list)) and len(value) == 3 and value[0] == "cmk_postprocessed":
        return password_store.extract_formspec_password(tuple(value))
    return str(value)


def _config_lines(config: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    def section(name: str) -> None:
        if lines:
            lines.append("")
        lines.append("[%s]" % name)

    def put(key: str, value: Any) -> None:
        lines.append("%s = %s" % (key, value))

    section("auth")
    if config.get("auth_url"):
        put("url", config["auth_url"])
    if config.get("auth_api_key"):
        put("api_key", _resolve_password(config["auth_api_key"]))
    if "zones" in config:
        put("zones", "yes" if config["zones"] else "no")
    if config.get("zone_refresh") is not None:
        put("zone_refresh", int(config["zone_refresh"]))
    if config.get("records"):
        put("records", config["records"])
    if config.get("max_zones") is not None:
        put("max_zones", int(config["max_zones"]))

    section("recursor")
    if config.get("recursor_url"):
        put("url", config["recursor_url"])
    if config.get("recursor_api_key"):
        put("api_key", _resolve_password(config["recursor_api_key"]))
    if config.get("recursor_enabled") is False:
        put("enabled", "no")

    return lines


def get_powerdns_files(conf: dict[str, Any]) -> FileGenerator:
    if not conf.get("deploy", True):
        return

    interval = conf.get("interval")
    yield Plugin(
        base_os=OS.LINUX,
        source=Path("powerdns"),
        target=Path("powerdns"),
        interval=int(interval) if interval else None,
    )

    config = conf.get("config")
    if config:
        yield PluginConfig(
            base_os=OS.LINUX,
            lines=_config_lines(config),
            target=Path("powerdns.cfg"),
            include_header=True,
        )


register.bakery_plugin(
    name="powerdns",
    files_function=get_powerdns_files,
)
