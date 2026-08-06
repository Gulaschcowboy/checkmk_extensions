#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery plug-in (v2) for "proxmox_node_swap".
# Turns the AgentConfig ruleset value into the deployed agent plug-in file.
# The plug-in is deployed to run synchronously (no caching).

from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, OS, Plugin


class ProxmoxNodeSwapConfig(BaseModel):
    deploy: bool


def get_proxmox_node_swap_files(conf: ProxmoxNodeSwapConfig) -> Iterable[Plugin]:
    if not conf.deploy:
        return

    yield Plugin(
        base_os=OS.LINUX,
        source=Path("proxmox_node_swap"),
    )


bakery_plugin_proxmox_node_swap = BakeryPlugin(
    name="proxmox_node_swap",
    parameter_parser=ProxmoxNodeSwapConfig.model_validate,
    default_parameters=None,
    files_function=get_proxmox_node_swap_files,
)
