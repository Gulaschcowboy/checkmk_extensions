# XenServer / XCP-ng (XAPI)

Checkmk special agent + check plugins that monitor a
[Citrix XenServer](https://www.xenserver.com/) or [XCP-ng](https://xcp-ng.org/)
pool through its management API (XAPI, XML-RPC over HTTPS port 443) and the
`rrd_updates` performance data of every pool member. No agent is needed on
the hypervisors, the agent works strictly read-only and only uses the Python
standard library. The feature set is modelled after Checkmk's built-in
VMware ESXi and Proxmox VE integrations.

XenServer Hosts:
<img width="1719" height="773" alt="grafik" src="https://github.com/user-attachments/assets/b5e18a6f-26ae-4b60-b22c-f8d42735b7c9" />

Xen VMs piggyback:
<img width="2157" height="295" alt="grafik" src="https://github.com/user-attachments/assets/720edb1a-4e2a-4469-a23a-56493fd3681f" />


It is not meant as a replacement for a Checkmk agent in dom0, but as an
addition. All services are prefixed with `XenServer` so they do not collide
with services of a dom0 agent.

## What it monitors

| Service | Where | Description |
|---|---|---|
| `XenServer Pool` | pool host | Coordinator and members, live / enabled (maintenance mode) state, missing performance data, HA overcommitment, failover to another member |
| `XenServer Alerts` | pool host | XAPI messages (XenCenter / Xen Orchestra alerts) of the last 24 h, priority 1-2 CRIT, 3 WARN; ignore patterns configurable |
| `XenServer SR <name>` | pool host (shared SRs) / XenServer host (local SRs) | SR capacity via the built-in filesystem logic (levels, trends, magic factor), PBD attach state, multipath paths |
| `XenServer SR I/O <name>` | as above | Throughput, IOPS, latency and queue length per SR |
| `XenServer Host` | XenServer host | Version, pool role, live / enabled, uptime, running VMs, clock offset to the Checkmk server, power consumption if reported |
| `XenServer Host CPU` | XenServer host | Physical CPU utilization, dom0 load, running vCPUs |
| `XenServer Host Memory` | XenServer host | Memory used by VMs and hypervisor, memory free for new VMs (no levels by default) |
| `XenServer Interface <device>` | XenServer host | Physical interfaces and bonds: link state, speed, bond membership, management role, throughput |
| `XenServer License` | XenServer host | License edition and expiry (XCP-ng: no expiry, always OK) |
| `XenServer Certificate <name>` | XenServer host | Expiry of host, internal and CA certificates known to XAPI |
| `XenServer Updates` | XenServer host | XenServer 8: latest synced updates applied, pending guidances (reboot / toolstack restart), age of the last update sync |
| `XenServer VM` | VM | Power state (configurable mapping), uptime, vCPUs, memory, guest OS, IP addresses, resident host |
| `XenServer VM CPU` | VM | vCPU utilization |
| `XenServer VM Memory` | VM | Assigned memory and in-guest usage (if the guest tools report it) |
| `XenServer VM Disk <device>` | VM | Throughput, IOPS and latency per virtual disk, with VDI / SR name and size |
| `XenServer VM Interface <device>` | VM | Throughput per virtual NIC, network and MAC |
| `XenServer VM Snapshots` | VM | Number of snapshots and age of the oldest one (default 7 / 30 days), snapshot schedule (VMSS) |
| `XenServer VM Guest Tools` | VM | Guest tools / PV drivers reporting, tools version |

Metrics reuse Checkmk's built-in metric names (CPU, memory, disk and
interface I/O, filesystem), so the standard graphs and perf-o-meters apply.

## Requirements

- Checkmk 2.3.0b1 or newer (`cmk_addons_plugins` API v2 layout).
  Developed and tested on 2.5.
- XenServer or XCP-ng (tested with XenServer 8.4), HTTPS (443) from the Checkmk server to
  the pool coordinator **and** to every pool member (performance data is
  fetched from each host directly).
- A XAPI user. `root` works. With Active Directory / RBAC the **Read Only**
  role should be sufficient, as the agent only calls `get_*`,
  `get_all_records`, `message.get_since` and `rrd_updates` (not tested yet).

## Installation

```sh
mkp add xenserver-1.0.0.mkp
mkp enable xenserver 1.0.0
```

Then in Checkmk:

1. Add the rule **Setup > Agents > VM, cloud, container > XenServer / XCP-ng via XAPI**
   for all XenServer hosts.
2. Enter user and password (the password store is supported)
3. Run service discovery and activate changes.
4. Create the piggyback hosts for the XenServer hosts and VMs (by hand or
   automatically with a *Dynamic host management* connection), named as
   shown in XenCenter (see naming options below).

Check the raw output with `cmk -d <pool host>`: you should see the sections
`xenserver_pool`, `xenserver_srs` and `xenserver_alerts` plus one piggyback
block per XenServer host and VM.

## Configuration options (special agent rule)

- **User / Password** - XAPI login; password store supported.
- **HTTPS port** - default `443`.
- **Disable TLS certificate verification** - for the default self-signed
  XenServer certificates.
- **Timeout per request**.
- **Failover addresses** - further pool members to try if the configured
  address is unreachable; members redirect to the current coordinator
  automatically.
- **Piggyback name of XenServer hosts** - name in XenCenter (`name_label`) or
  the dom0 host name.
- **Piggyback name of VMs** - VM name or VM UUID (use the UUID if VM names are
  not unique).
- **Alert window** - how many hours of XAPI messages are evaluated (default 24).
- **Do not create piggyback data for VMs** - pool and hosts only.

## Check parameters

Rulesets under **Setup > Services > Service monitoring rules > Virtualization**:
`XenServer pool`, `XenServer alerts`, `XenServer host`,
`XenServer host / VM CPU utilization`, `XenServer host / VM memory usage`,
`XenServer license`, `XenServer certificates`, `XenServer updates`,
`XenServer SR / VM disk I/O`, `XenServer VM state`, `XenServer VM snapshots`,
`XenServer VM guest tools`.
SR capacity uses the built-in **Filesystems (used space and growth)** ruleset.

## Notes

- Performance counters are rates: right after the first discovery / check the
  I/O and CPU services may be empty for one cycle while the counters are
  initialized.
- By default `Halted` VMs are OK; use the *XenServer VM state* rule to alert
  on VMs that must always run.
- Multi-host pools (failover, per-member performance data, HA, shared SRs
  with multipath) are implemented, but so far only validated against a
  simulated pool; single-host pools are validated against XenServer 8.4.

## Changelog

- **1.0.0** - Initial release.

## Layout

```
cmk_addons_plugins/xenserver/
  agent_based/        xenserver_{pool,host,vm}.py
  checkman/           manpages for each check
  graphing/           XenServer-specific metrics (snapshot age, running VMs)
  lib/                shared helpers
  libexec/            agent_xenserver  (the special agent)
  rulesets/           special-agent + check-parameter rulesets
  server_side_calls/  builds the agent command line
xenserver.manifest.temp
xenserver-1.0.0.mkp
```
