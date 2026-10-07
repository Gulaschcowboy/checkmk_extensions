# Citrix Virtual Apps and Desktops (CVAD REST API)

Checkmk special agent that monitors Citrix Virtual Apps and Desktops (CVAD,
formerly XenApp/XenDesktop) entirely over HTTPS, using the on-premises CVAD
REST API (Citrix Orchestration Service) instead of a PowerShell script
running locally on the Delivery Controller.

## Why

Citrix ships a Windows agent plug-in, `citrix_farm.ps1`, that uses the local
Citrix Broker PowerShell SDK (`Get-BrokerMachine`, `Get-BrokerSession`, ...)
and must run directly on a Delivery Controller. This special agent is an
alternative data source for environments where:

- running custom scripts on the Delivery Controller is not desired or not
  possible (e.g. managed/outsourced Citrix farms), or
- you simply want to pull the data remotely from the Checkmk server, the
  same way other special agents (Proxmox, pfSense, ...) already work in this
  repository.

## What it does

The agent authenticates with a Citrix admin user/password against
`/cvad/manage/Tokens`, then reads `/cvad/manage/Machines` and
`/cvad/manage/Sessions`. For every VDA machine it creates a piggyback host
and emits:

- `citrix_state` (catalog, controller, delivery group, fault/maintenance/
  power/registration state, AgentVersion)
- `citrix_serverload` (LoadIndex, if reported)
- `citrix_sessions` (session/active/inactive counts)

For every hypervisor host hosting at least one machine, it additionally
emits a `citrix_hostsystem` piggyback section (VM name + pool name).

**These are the exact same sections Citrix's own `citrix_farm.ps1` produces.**
This package therefore ships **no custom check plug-ins** — it reuses
Checkmk's built-in `citrix_state`, `citrix_serverload`, `citrix_sessions`
and `citrix_hostsystem` checks unchanged. There is no collision with
Checkmk's built-in Citrix monitoring at the check-plug-in level, and no
deployment conflict as long as you don't run both agents against the same
machines at the same time.

### Known limitation

The CVAD REST API has no documented equivalent of `Get-BrokerController`.
Delivery Controller health/licensing (the `citrix_controller` service) is
therefore **not** covered by this special agent and still requires
`citrix_farm.ps1` on the DDC if you need it.

## Requirements

- Citrix Virtual Apps and Desktops, on-premises, with Citrix Orchestration
  Service (CVAD 2212 or newer).
- A Citrix admin account; "Read-Only Administrator" is sufficient.
- Network access from the Checkmk server to the Delivery Controller over
  HTTPS (default port 443).

## Configuration

Setup -> Agents -> Other integrations -> "Citrix Virtual Apps and Desktops
(CVAD REST API)". Assign the rule to a host representing the Delivery
Controller (or set the DDC address explicitly if it differs from the host's
IP address). The password can be stored in the Checkmk password store.

Verified against Checkmk 2.5 and 3.0 (`cmk_addons_plugins` with the
`rulesets`/`server_side_calls` v1 API, unchanged between both versions).
