# Hermes Agent Dashboard (REST API)

Checkmk special agent + check plugins that monitor a
[Hermes Agent](https://hermes-agent.nousresearch.com/) installation through
its web dashboard's public REST API (`hermes dashboard`, default port 9119).

## What it monitors

One host runs the special agent against the dashboard's `GET /api/status`
endpoint; services are auto-discovered:

| Service | Description |
|---|---|
| `Hermes Dashboard` | Overview: agent version, overall status, pending update, active session count |
| `Hermes Gateway` | Gateway process state (running/stopped/starting/error/crashed), last exit reason |
| `Hermes Platform <name>` | Per-platform connection state (Telegram, Discord, Slack, WhatsApp, ...), one per configured platform |
| `Hermes Component <name>` | Per internal component health (gateway, dashboard, storage, platforms), one per component |
| `Hermes Usage Cost` | Optional: token/cost usage over a rolling window (estimated cost, input/output/cache-read tokens, sessions, API calls), fetched from the authenticated `GET /api/analytics/usage` endpoint |

## Requirements

- Checkmk 2.3.0b1 or newer (uses the `cmk_addons_plugins` API v2 layout).
- A running Hermes Agent web dashboard (`hermes dashboard`) reachable over
  the network. `GET /api/status` is a public, unauthenticated endpoint by
  design (see Hermes docs), so no credentials are required in the default
  case — the special agent supports optional HTTP basic-auth only for setups
  where a reverse proxy in front of the dashboard adds its own auth layer.
- For the optional `Hermes Usage Cost` service: the dashboard's own login
  credentials (`dashboard.basic_auth` in `config.yaml` /
  `HERMES_DASHBOARD_BASIC_AUTH_PASSWORD(_HASH)`), since `/api/analytics/usage`
  sits behind the dashboard's own cookie-session login gate — a different
  auth layer than the reverse-proxy basic-auth above.

## Installation

```sh
mkp add hermes_dashboard-1.2.0.mkp
mkp enable hermes_dashboard 1.2.0
```

Then in Checkmk:

1. Create a host for the machine running the Hermes dashboard.
2. Add the rule **Setup > Agents > Other integrations > Hermes Agent dashboard (REST API)**.
3. Adjust port/protocol if the dashboard isn't on the default `http://<host>:9119`.
4. To also monitor token/cost usage, enable **Fetch token/cost usage data**
   and set the dashboard login username/password (store the password via
   Checkmk's password store, not typed inline in the rule, so it survives
   config exports without leaking the plaintext).
5. Run service discovery and activate changes.

## Configuration options (WATO ruleset)

- **HTTP port** — default `9119`
- **Protocol** — `http` (default) or `https`
- **Server address (host/IP)** — optional override for the address the
  special agent connects to; leave empty to use the host's configured IP
  address (Checkmk default). Set this when the dashboard's TLS certificate
  is only valid for a hostname and the monitoring host is configured by IP
  (avoids `SSL: CERTIFICATE_VERIFY_FAILED ... IP address mismatch`).
- **HTTP basic-auth username/password** — only needed behind a reverse proxy
- **Request timeout** — default 10s
- **Fetch token/cost usage data** — logs in via `POST /auth/password-login`
  (provider `basic`) using the username/password above, then queries
  `GET /api/analytics/usage` for the `Hermes Usage Cost` service. Off by
  default.
- **Usage reporting window (days)** — passed as `?days=` to the usage
  endpoint, default 1
- **Disable TLS certificate verification** — HTTPS only; needed when the
  dashboard is reached via a bare IP address or a self-signed certificate

Each discovered check also has its own check-parameter ruleset to adjust the
state mapping (e.g. state when the gateway is stopped, state when a platform
is disconnected, state when a component reports recent unhandled errors or
fewer connected platforms than configured, or cost warning/critical levels
for `Hermes Usage Cost`).

## Ideas for further checks (not yet implemented)

The dashboard's broader REST surface (see the
[API Server](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server/)
and [Web Dashboard](https://hermes-agent.nousresearch.com/docs/user-guide/features/web-dashboard/)
docs) exposes more that could become additional checks later, e.g.:

- `GET /health/detailed` (API server, when enabled) — richer readiness
  breakdown: config/state DB/model/disk-space/pending processes/active
  delegations.
- `GET /api/sessions` — active/recent session count and staleness (e.g. no
  session activity for N hours could indicate a stuck integration).
- `GET /api/jobs` (cron jobs) — failed/paused scheduled jobs.
- `GET /api/logs` — recent ERROR-level log line count as an early-warning
  metric.

## Layout

```
cmk_addons_plugins/hermes_dashboard/
  agent_based/        hermes_dashboard.py (overview, gateway, platform, component, usage checks)
  checkman/           manpages for each check
  graphing/           metrics (active_sessions, hermes_usage_cost, tokens, sessions, api_calls)
  libexec/            agent_hermes_dashboard  (the special agent)
  rulesets/           special-agent + check-parameter rulesets
  server_side_calls/  builds the agent command line
hermes_dashboard.manifest.temp
hermes_dashboard-1.2.0.mkp
```
