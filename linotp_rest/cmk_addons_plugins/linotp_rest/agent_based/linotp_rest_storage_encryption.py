#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""LinOTP storage encryption status (/monitoring/storageEncryption)."""

from __future__ import annotations

import json
from typing import Any

from cmk.agent_based.v2 import AgentSection, CheckPlugin, Result, Service, State


def parse_linotp_rest_storage_encryption(string_table: list[list[str]]) -> dict[str, Any]:
    raw = " ".join(part for row in string_table for part in row).strip()
    if not raw:
        return {"ok": False, "error": "Empty section"}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"Invalid JSON: {exc}"}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected data"}


def discover_linotp_rest_storage_encryption(section: dict[str, Any]):
    yield Service()


def check_linotp_rest_storage_encryption(section: dict[str, Any]):
    if not section.get("ok"):
        yield Result(state=State.CRIT, summary=str(section.get("error") or "Could not read storage encryption status"))
        return

    if not section.get("encryption"):
        yield Result(state=State.CRIT, summary="Storage encryption is NOT active")
        return

    module_type = section.get("cryptmodul_type") or "?"
    module_name = section.get("cryptmodul_name") or "?"
    yield Result(state=State.OK, summary=f"Encryption active ({module_type}/{module_name})")


agent_section_linotp_rest_storage_encryption = AgentSection(
    name="linotp_rest_storage_encryption",
    parse_function=parse_linotp_rest_storage_encryption,
)

check_plugin_linotp_rest_storage_encryption = CheckPlugin(
    name="linotp_rest_storage_encryption",
    service_name="LinOTP Storage Encryption",
    discovery_function=discover_linotp_rest_storage_encryption,
    check_function=check_linotp_rest_storage_encryption,
)
