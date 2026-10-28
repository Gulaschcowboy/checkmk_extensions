#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Agent Bakery plug-in for "sshd_crypto".
# Turns the AgentConfig ruleset value into the deployed agent plug-in file.

from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from cmk.bakery.v2_unstable import BakeryPlugin, OS, Plugin


class SshdCryptoConfig(BaseModel):
    deployment: tuple[Literal["do_not_deploy", "sync", "cached"], float | None]


def get_sshd_crypto_files(conf: SshdCryptoConfig) -> Iterable[Plugin]:
    if conf.deployment[0] == "do_not_deploy":
        return

    yield Plugin(
        base_os=OS.LINUX,
        source=Path("sshd_crypto"),
        interval=conf.deployment[1] if conf.deployment[0] == "cached" else None,
    )


bakery_plugin_sshd_crypto = BakeryPlugin(
    name="sshd_crypto",
    parameter_parser=SshdCryptoConfig.model_validate,
    default_parameters=None,
    files_function=get_sshd_crypto_files,
)
