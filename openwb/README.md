# ⚠️ Work in Progress

**This MKP is under active development and not yet finished.** Version numbers
below 1.0.0 indicate a pre-release/WIP state — expect breaking changes,
incomplete features, and limited testing. Use at your own risk; feedback and
issues are welcome.

# openWB wallbox (simpleAPI, read-only)

Checkmk special agent that monitors an [openWB](https://openwb.de/) wallbox
controller through its read-only simpleAPI HTTP endpoint. Never issues write
requests to the wallbox.

## What it monitors

The agent auto-discovers all devices by probing numeric device IDs (the
simpleAPI has no built-in device-listing call) — no manual ID configuration
needed:

| Service | Description |
|---|---|
| `openWB Chargepoint <id>` | Charging power, vehicle state of charge, plug/charge state, charge mode |
| `openWB Counter <id>` | Grid import/export power and frequency |
| `openWB Battery <id>` | State of charge, charge/discharge power |
| `openWB PV <id>` | Generation power, daily/monthly/yearly yield |

## Requirements

- Checkmk 2.3.0b1 or newer (uses the `cmk_addons_plugins` API v2 layout).
- Network access to the openWB controller's simpleAPI HTTP endpoint (no
  authentication required by the simpleAPI itself).

## Installation

```sh
mkp add openwb-0.0.9.mkp
mkp enable openwb 0.0.9
```

Then in Checkmk:

1. Create a host for the openWB controller.
2. Add the rule **Setup > Agents > Other integrations > Hardware > openWB wallbox (simpleAPI)**.
3. Adjust port / HTTPS / TLS check as needed.
4. Run service discovery and activate changes.

## Configuration options (WATO ruleset)

- **HTTP(S) port**
- **Use HTTPS**
- **Disable TLS certificate verification** — for self-signed certs
- **Request timeout**
- **Discovery options** — "Highest ... ID to probe" for chargepoints, counters,
  batteries and PV inverters, to bound the ID-scan range on installations with
  unusually high device IDs.

## Layout

```
cmk_addons_plugins/openwb/
  agent_based/        openwb.py (check plugins)
  checkman/            manpages for each check
  graphing/            metrics/graphs
  libexec/             agent_openwb  (the special agent)
  rulesets/            special-agent + check-parameter rulesets
  server_side_calls/   builds the agent command line
openwb.manifest.temp
openwb-0.0.9.mkp
```
