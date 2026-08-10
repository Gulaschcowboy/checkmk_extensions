# PowerDNS Authoritative Server and Recursor

Checkmk check plugins that monitor the **PowerDNS Authoritative Server** and the
**PowerDNS Recursor** through their built-in HTTP APIs, with a control-socket
fallback (`pdns_control` / `rec_control`) when the API is unavailable.

## Changelog

### 1.2.2
- **Auth API auto-detection fix:** the authoritative endpoint auto-detection
  required an explicit `webserver=yes` line in `pdns.conf`. PowerDNS enables its
  built-in webserver (and REST API) implicitly with `api=yes`, so setups that set
  only `api=yes` got the statistics section (control-socket fallback) but an empty
  `powerdns_auth_zones` section (`zone inventory needs the HTTP API`). Detection
  now treats `api=yes` as sufficient, so the zone inventory works without a
  separate `webserver=yes` line.

### 1.2.1
- **Bakery API-key fix:** the CEE agent bakery wrote the API key into
  `/etc/check_mk/powerdns.cfg` as the raw `('cmk_postprocessed',
  'explicit_password', (id, secret))` form_spec tuple instead of the plaintext
  secret. The agent plugin then sent that repr as the `X-API-Key` header and the
  PowerDNS HTTP API answered **401**, leaving the zone section empty. The bakery
  now resolves the secret with `password_store.extract_formspec_password`.
- **Agent-plugin crash fix:** an empty `webserver-address=` in `pdns.conf`
  triggered `list index out of range` in the authoritative endpoint
  auto-detection (`"".split()[0]`). It now falls back to `127.0.0.1` for an empty
  or whitespace-only value.
- **Version alignment:** the agent plugin's `PLUGIN_VERSION` constant (was stuck
  at `1.0.0`) now tracks the package version.

## What it monitors

An agent plugin (`agents/plugins/powerdns`) runs on the monitored host and emits
three JSON sections; services are auto-discovered:

<img width="1247" height="576" alt="image" src="https://github.com/user-attachments/assets/a8f48b41-5f38-44fe-86e7-e4aca76f06fe" />


| Service | Description |
|---|---|
| `PowerDNS Authoritative Server: Status` | Daemon status and security-status |
| `PowerDNS Authoritative Server: Query rates` | Query and error rates |
| `PowerDNS Authoritative Server: Caches` | Packet and query cache efficiency |
| `PowerDNS Authoritative Server: Latency` | Answer latency |
| `PowerDNS Authoritative Server: Zone summary` | Zone count / truncation state |
| `PowerDNS Authoritative Server: Single zone` | One per zone: record count metric, serial vs. notified_serial (primaries), last_check age (secondaries) |
| `PowerDNS Recursor: Status` | Daemon status and capacity |
| `PowerDNS Recursor: Query rates` | Query rates and upstream problems |
| `PowerDNS Recursor: Caches` | Record and packet cache efficiency |
| `PowerDNS Recursor: Latency` | Answer latency incl. answer-time distribution |
| `PowerDNS Recursor: DNSSEC validation` | DNSSEC validation results |

## Requirements

- Checkmk **2.5.0b1** or newer (`version.min_required`; packaged on 2.5.0). Uses
  the `cmk_addons_plugins` API v2 layout.
- The agent plugin deployed to each monitored PowerDNS host (manually or via the
  bundled agent bakery ruleset, CEE only).
- Read access to the PowerDNS HTTP API (API key) for full functionality; without
  it the plugin falls back to the control socket (statistics only, no zones).

## Installation

```sh
mkp add powerdns-1.2.2.mkp
mkp enable powerdns 1.2.2
```

Then:

1. Deploy the agent plugin `powerdns` to the monitored host under the agent's
   `plugins/` directory (CEE: use the **PowerDNS** agent bakery rule instead).
2. Optionally drop a `/etc/check_mk/powerdns.cfg` (see
   [`doc/powerdns.cfg.example`](doc/powerdns.cfg.example)) — without it the plugin
   auto-detects the webserver address and API key from the PowerDNS config.
3. Run service discovery and activate changes.

## Configuration

The agent plugin is configured through the optional
`/etc/check_mk/powerdns.cfg`. Without it everything is auto-detected from
`pdns.conf` / `recursor.yml`. See `doc/powerdns.cfg.example` for every option
(API URL/key override, zone inventory, record-counting strategy, budgets).

Check thresholds are configured via the WATO rulesets shipped in the package
(auth status, recursor status, zone parameters, and the CEE agent-bakery rule).

## Layout

```
powerdns/
├── cmk_addons_plugins/powerdns/
│   ├── agent_based/   powerdns_auth.py, powerdns_auth_zones.py, powerdns_recursor.py
│   ├── checkman/      11 manpages (catalog app/powerdns)
│   ├── graphing/      powerdns.py (88 metrics)
│   └── rulesets/      powerdns_auth/recursor/zones/bakery.py
├── agents/plugins/powerdns                          # the agent plugin
├── lib/python3/cmk/base/cee/plugins/bakery/powerdns.py   # agent bakery (CEE)
├── doc/powerdns.cfg.example                         # sample config
├── powerdns.manifest.temp                           # MKP manifest
└── powerdns-1.2.2.mkp                               # built package
```
