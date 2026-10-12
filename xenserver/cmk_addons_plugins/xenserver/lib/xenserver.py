#!/usr/bin/env python3
"""Shared helpers for the XenServer / XCP-ng check plugins."""
import json

from cmk.agent_based.v2 import CheckResult, StringTable, check_levels, render


def json_lines(string_table: StringTable) -> list:
    """Sections use sep(0) and carry one JSON document per line."""
    out = []
    for line in string_table:
        if not line or not line[0].strip():
            continue
        try:
            out.append(json.loads(line[0]))
        except ValueError:
            continue
    return out


def _per_second(value: float) -> str:
    return "%.1f/s" % value


def check_disk_io(params, data) -> CheckResult:
    """Shared by SR I/O and VM disks; latencies come in microseconds."""
    for key, metric, label, render_func in (
        ("read_bytes", "disk_read_throughput", "Read", render.iobandwidth),
        ("write_bytes", "disk_write_throughput", "Write", render.iobandwidth),
        ("read_ios", "disk_read_ios", "Read operations", _per_second),
        ("write_ios", "disk_write_ios", "Write operations", _per_second),
    ):
        if data.get(key) is not None:
            yield from check_levels(data[key], metric_name=metric, label=label, render_func=render_func)
    for key, metric, label, pkey in (
        ("read_latency_us", "disk_read_latency", "Read latency", "read_latency"),
        ("write_latency_us", "disk_write_latency", "Write latency", "write_latency"),
    ):
        if data.get(key) is not None:
            yield from check_levels(data[key] / 1e6, levels_upper=params.get(pkey),
                                    metric_name=metric, label=label, render_func=render.timespan)
    if data.get("queue") is not None:
        yield from check_levels(data["queue"], metric_name="disk_queue_length",
                                label="Queue length", render_func=lambda v: "%.2f" % v,
                                notice_only=True)
