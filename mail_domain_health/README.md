# Mail domain health (plugin + dashboard)

> ⚠️ **Work in progress.** This package is still under active development.
> **Expect incompatible changes** between versions — rulesets, service names,
> section formats and metrics may change without a migration path. Do not rely on
> it for production monitoring yet.

Checkmk special-agent plugin that monitors the **DNS-based mail security posture**
of one or more domains, plus a bundled overview dashboard. Author: Christian Wirtz
(upstream). This subdirectory ships version **1.4.0**, redistributed **unchanged**
from the upstream `.mkp`; the packaging `download_url` points at this repo.

The special agent uses only the **Python standard library** (DNS, plus HTTPS/SMTP
for some optional features) — there is **no agent deployment** on the monitored
host. Configure it via *Setup → Agents → Other integrations → Mail domain health*.

## What it monitors

Nine independently switchable checks (SPF and DMARC on by default), one service
each:
<img width="1378" height="184" alt="image" src="https://github.com/user-attachments/assets/d5047c02-082f-40ad-8572-2a69b0b6a0ad" />


| Service | Description |
|---|---|
| `Mail domain health: SPF record` | SPF TXT record + recursive DNS lookup count (RFC 7208 10-lookup limit) |
| `Mail domain health: DMARC record` | DMARC policy record (`_dmarc.<domain>`) |
| `Mail domain health: DKIM records` | DKIM public-key records for configured selectors (global + per-domain) |
| `Mail domain health: DNSBL/RBL listings` | DNSBL/RBL listings per IP (IPv4+IPv6), optional MX resolution |
| `Mail domain health: domain-based blacklists` | Domain-based blacklists (DBL/SURBL/URIBL) |
| `Mail domain health: MTA-STS / TLS-RPT` | MTA-STS policy (TXT + HTTPS policy file) and TLS-RPT record |
| `Mail domain health: DANE/TLSA` | DANE/TLSA records, optional certificate verification |
| `Mail domain health: BIMI record` | BIMI record + optional logo/VMC URL checks |
| `Mail domain health: domain registration expiry` | RDAP registration expiry + registrar |

DNSSEC is **not** part of this package — it lives in the separate `dnssec_health`
plugin.

Ships Perf-O-Meters, check manuals (checkman) for all nine checks, and a
free-dashlet **overview dashboard** (`Mail domain health`) that aggregates the
posture across all monitored domains.

No blacklist zones are shipped by default — you configure which DNSBL/RBL and
domain-blacklist zones to query (the ruleset field help lists copyable
suggestions). Rules from earlier versions are migrated automatically.

## Requirements

- Checkmk **2.5.0** or newer (`version.min_required`; packaged on 2.5.0). Uses the
  `cmk_addons_plugins` API v2 layout and ships a `gui` dashboard.
- No agent plugin on the monitored host — the special agent runs on the Checkmk
  site and resolves everything over DNS (plus HTTPS/SMTP for MTA-STS/DANE/BIMI).

## Installation

```sh
mkp add mail_domain_health-1.4.0.mkp
mkp enable mail_domain_health 1.4.0
```

Then:

1. Add a **Mail domain health** rule under *Setup → Agents → Other integrations*
   and list the domains to monitor (enable optional checks as needed).
2. Assign it to a host (any host works — the agent only does DNS/HTTPS/SMTP
   lookups, it does not talk to the host itself).
3. Run service discovery and activate changes.
4. Optionally add the shipped **Mail domain health** dashboard to your view.

## Layout

```
mail_domain_health/
├── cmk_addons_plugins/mail_domain_health/
│   ├── agent_based/        mail_domain_health.py (9 check plugins + sections)
│   ├── checkman/           9 manpages (bimi, dane, dkim, dmarc, domain_bl, mta_sts, rbl, rdap, spf)
│   ├── graphing/           mail_domain_health.py (6 metrics + Perf-O-Meters)
│   ├── libexec/            agent_mail_domain_health (special agent, stdlib only)
│   ├── rulesets/           special_agent + check_parameters (9 per-check rulesets)
│   └── server_side_calls/  mail_domain_health.py
├── gui/dashboard/mail_domain_health.mk               # overview dashboard
├── mail_domain_health.manifest.temp                  # MKP manifest
└── mail_domain_health-1.4.0.mkp                      # built package (upstream, unchanged)
```
