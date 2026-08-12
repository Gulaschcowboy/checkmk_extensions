#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery plug-in (v2) for "zfs_arc".
# Turns the AgentConfig ruleset value into the deployed agent plug-in file.
# The plug-in is deployed to run synchronously (no caching) -- reading two
# small /proc files per agent run is effectively free.

from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, OS, Plugin


class ZfsArcConfig(BaseModel):
    deploy: bool


def get_zfs_arc_files(conf: ZfsArcConfig) -> Iterable[Plugin]:
    if not conf.deploy:
        return

    yield Plugin(
        base_os=OS.LINUX,
        source=Path("zfs_arc"),
    )


bakery_plugin_zfs_arc = BakeryPlugin(
    name="zfs_arc",
    parameter_parser=ZfsArcConfig.model_validate,
    default_parameters=None,
    files_function=get_zfs_arc_files,
)
