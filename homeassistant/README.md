# Home Assistant

Checkmk special agent that queries a **Home Assistant** instance and creates
Checkmk piggyback hosts grouped by Home Assistant **area/room**, with one
service per imported entity.

## How it works

The special agent (`libexec/agent_homeassistant`) fetches entity states via
the Home Assistant **REST API** (`/api/states`) and device/entity/area
registries via the Home Assistant **WebSocket API** (`/api/websocket`). The
WebSocket client is implemented with the Python standard library only, so no
extra dependency beyond `requests` (already used by the Checkmk agent stack)
is required.

Entities are grouped by their effective area — an entity-level area
assignment wins, otherwise the area is inherited from the entity's device —
and emitted as piggyback data for one generated host per area, named
`<host_prefix><area-slug>` (default prefix `ha-`, e.g. `ha-living-room`).
Entities without an area go to `<host_prefix>unassigned`.

A `Home Assistant API` service on the queried host reports the special
agent's own health: REST/WebSocket success, number of selected/emitted
entities, number of generated piggyback hosts and query duration. It goes
WARN when limits (max hosts / max entities) were reached or other non-fatal
issues occurred, and CRIT when the REST or WebSocket query failed entirely.

## Layout

```
cmk_addons_plugins/homeassistant/
├── libexec/agent_homeassistant                # special agent (REST + stdlib WebSocket client)
├── agent_based/
│   ├── homeassistant_source.py                # AgentSection + CheckPlugin for the "Home Assistant API" service
│   └── homeassistant.py                       # piggyback entity sections/services
├── rulesets/special_agent.py                  # WATO: URL, token, domains, filters, limits
├── server_side_calls/special_agent.py         # wires the ruleset to the agent
└── checkman/homeassistant                     # manpage
```

## Setup

1. Install the package: `mkp add homeassistant-0.2.4.mkp && mkp enable homeassistant 0.2.4`.
2. Create a Home Assistant **long-lived access token** (Home Assistant →
   profile → Security → Long-lived access tokens).
3. In the Checkmk GUI: **Setup › Agents › Other integrations › Home
   Assistant**. Configure the base URL, the token (the Checkmk password
   store can be used), and the entity domains to import.
4. Assign the rule to a host, run service discovery on that host to get the
   `Home Assistant API` service, then create/discover the generated
   piggyback hosts (`ha-<area>`, `ha-unassigned`) to see the per-entity
   services.

## Configuration options

| Option | Description |
|--------|-------------|
| Home Assistant URL | Base URL, e.g. `https://homeassistant.example.org:8123` |
| Long-lived access token | Stored via the Checkmk password store |
| Verify TLS certificate | Disable only for self-signed/internal setups |
| Entity domains | Comma-separated Home Assistant domains to import (default `sensor,binary_sensor`) |
| Include/exclude regular expression | Optional filters matched against entity ID and friendly name |
| Ignore unavailable entities | Skip entities whose state is exactly `unavailable` (`unknown` is still imported) |
| Piggyback host prefix | Default `ha-`; lowercase letters, digits and hyphens only |
| API timeout | Per-request timeout in seconds |
| Warn when entity data is older than seconds | Stale-data threshold, `0` disables the check |
| Maximum generated piggyback hosts / imported entities | Safety limits to protect the Checkmk service budget, `0` = unlimited |

## Verified against

Checkmk 2.5.0 (CEE), Home Assistant, REST + WebSocket API.
