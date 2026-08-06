# Proxmox Node Swap Usage — Checkmk MKP (agent-based + bakery)

Checkmk MKP that monitors the **swap usage of a Proxmox VE node** and pinpoints
the virtual machines (QEMU) and containers (LXC) responsible for the host swap
being consumed.

This is the **agent-based + Agent-Bakery successor** of the former
`proxmox_node_swap` *local check* (≤ 1.1.2). The monitoring logic now lives in a
proper server-side check plug-in; the node only ships a lightweight agent
plug-in that collects raw data.

| Component | Purpose |
|-----------|---------|
| `agents/proxmox_node_swap` | Agent plug-in on the PVE node. Emits one JSON section `<<<proxmox_node_swap>>>` (node swap from `/proc/meminfo`, per-guest host swap: LXC via cgroup v2 `memory.swap.current`, QEMU via the VM process `VmSwap`). |
| `agent_based/proxmox_node_swap.py` | Section parser + check plug-in. Service `Proxmox Node Swap Usage`. |
| `rulesets/proxmox_node_swap.py` | Check-parameter ruleset — warn/crit levels on percent swap used. |
| `rulesets/agent_config_proxmox_node_swap.py` | Agent-Bakery ruleset (deploy + sync/cached interval). |
| `bakery/bakery_plugin_proxmox_node_swap.py` | Bakery plug-in (v2 API) that installs the agent plug-in. |
| `graphing/swap.py` | Metric `swap_used_bytes` + a 0–100 % perf-o-meter on `swap_used_percent`. |
| `checkman/proxmox_node_swap` | Man page. |

The service state is derived from configurable levels on the percentage of the
node's total swap in use (default WARN 50 % / CRIT 80 %). The summary lists the
top swap-consuming guests; the details view lists the top ten plus a swap
accounting breakdown (guests vs. host/system). LXC containers also show their
usage relative to their own swap limit.

## Requirements

- Checkmk 2.3.0 or newer (uses `cmk.agent_based.v2`, `cmk.rulesets.v1`,
  `cmk.graphing.v1`).
- The Agent Bakery (bakery plug-in) requires a **commercial edition**
  (Enterprise / Cloud / MSP). The check itself works on Raw too — you just
  deploy the agent plug-in manually there.
- The PVE node's agent runs as **root** (default), required to read the cgroup /
  proc / `/etc/pve` values.

## Installation

```bash
mkp add proxmox_node_swap-2.0.0.mkp
mkp enable proxmox_node_swap 2.0.0
```

### Deploy the agent plug-in

**With the bakery (recommended):** create a rule under
*Setup → Agents → Agent rules → Proxmox node swap (Linux)*, bake and sign the
agent, and roll it out to the Proxmox node(s).

**Manually (any edition):**

```bash
# on the Proxmox node
cp proxmox_node_swap /usr/lib/check_mk_agent/plugins/proxmox_node_swap
chmod +x /usr/lib/check_mk_agent/plugins/proxmox_node_swap
# test:
/usr/lib/check_mk_agent/plugins/proxmox_node_swap
```

Then on the Checkmk server, rediscover the host — the `Proxmox Node Swap Usage`
service appears.

## Migrating from the local check (≤ 1.1.2)

The old version shipped a *local check* that produced the identical service
name (`Proxmox Node Swap Usage`), so on the surface nothing changes. Differences:

- Remove the old local check from the node
  (`/usr/lib/check_mk_agent/local/proxmox_node_swap`) — the new agent plug-in
  lives under `plugins/`, not `local/`.
- Thresholds are no longer configured via `PVE_SWAP_WARN` / `PVE_SWAP_CRIT`
  environment variables but via the WATO rule *"Proxmox node swap usage"*.
- Perfdata metric names are unchanged (`swap_used_percent`, `swap_used_bytes`),
  so historical graphs continue.

## Building from source

The plug-in uses the single-part `cmk_addons_plugins` family layout, so the
stdlib-only builder works:

```bash
python3 tools/build_mkp.py    # run from this directory
python3 tools/verify_mkp.py . proxmox_node_swap-2.0.0.mkp proxmox_node_swap
```

Or rebuild on a site with `mkp package proxmox_node_swap`.

## License

GPLv2. Original local check by Christian Wirtz; agent-based + bakery rework
retains the original data-collection logic.
