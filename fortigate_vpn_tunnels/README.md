# FortiGate IPsec VPN tunnels

## What it monitors

Checkmk's buildin Fortigate plug-in creates only one summary service for all IPSEC VPN Tunnels.
This extension creates **one service per IPsec VPN tunnel**(phase 2 selector)
on Fortinet FortiGate firewalls.

<img width="1451" height="304" alt="grafik" src="https://github.com/user-attachments/assets/c66d37c9-9756-4c3f-b4c0-52ac33de62ee" />

Per service (`VPN IPSec Tunnel <phase 2 name>`):

- Status up/down — down is CRIT by default, configurable per tunnel
  (e.g. OK for on-demand tunnels).
- Phase 1 name (if it differs from the phase 2 name), remote gateway,
  local/remote selectors.
- Details: VDOM, local gateway, SA lifetime and remaining SA lifetime,
  traffic counters. FortiOS reports the traffic counters per phase 1, so all
  selectors of the same phase 1 show the same values.

If the same phase 2 name exists in several VDOMs, the VDOM name is appended to
the item.

## Requirements

- Checkmk 2.3.0p1 or newer.
- FortiGate monitored via SNMP

## Installation

```bash
mkp add fortigate_vpn_tunnels-1.0.0.mkp
mkp enable fortigate_vpn_tunnels 1.0.0
```

Then re-run the service discovery of your FortiGate hosts.

## Configuration

- **Setup > Services > Service monitoring rules > FortiGate IPsec VPN tunnel
  (per tunnel)** — state if a tunnel is down. Restrict the rule to single
  tunnels via the service condition.
- **Setup > Services > Discovery rules > FortiGate IPsec VPN tunnel
  discovery** — by default every configured tunnel gets a service; optionally
  only tunnels that are up at discovery time.

If you only want the per-tunnel services, you can disable the summary service
"VPN IPSec Tunnels" via the rule "Disabled services".

## Changelog

- **1.0.0** — Initial release. Verified against FortiOS 7.4.
