# Proxmox Mail Gateway (REST API) — Checkmk Special Agent

Checkmk MKP that monitors a Proxmox Mail Gateway (PMG) node through its REST
API. PMG has no API-token mechanism, so authentication uses a ticket obtained
via username/password (`POST /access/ticket`) — use a dedicated, unprivileged
audit user with the built-in **Audit** role, not an admin account.

Not meant as an replacement for the Linux agent, but as an addition.
<img width="1292" height="451" alt="image" src="https://github.com/user-attachments/assets/49e33c19-ae67-4b04-a338-f81be016cee3" />


| Check plugin           | Services                                                        |
|-------------------------|------------------------------------------------------------------|
| `pmg_mail`              | Mail throughput and spam/virus junk ratio                       |
| `pmg_rejects`           | SMTP early rejects (RBL / PREGREET) over the reporting window   |
| `pmg_queue`             | Postfix queue depth (one service per queue: active, deferred, hold, incoming) |
| `pmg_quarantine_spam`   | Spam quarantine size (mail count)                                |
| `pmg_quarantine_virus`  | Virus quarantine size (mail count)                               |
| `pmg_clamav`            | ClamAV virus signature database freshness                        |
| `pmg_spamassassin`      | SpamAssassin rule channel update status (one service per channel)|
| `pmg_node_status`       | Node uptime, cluster database sync state, kernel version         |
| `pmg_updates`           | Number of pending package updates                                |
| `pmg_subscription`      | Subscription status                                              |
| `pmg_certificates`      | TLS certificate expiry (one service per certificate)             |

All warn/crit thresholds are configurable via WATO rules under
*Setup → Service monitoring rules* (one ruleset per check listed above).

## Layout

```
cmk_addons_plugins/pmg/
├── libexec/agent_pmg                    # special agent (REST API poller, ticket auth)
├── agent_based/                         # check plugins (parse + evaluate sections)
│   ├── pmg_statistics.py                # pmg_mail, pmg_rejects
│   ├── pmg_queue.py                     # pmg_queue
│   ├── pmg_quarantine.py                # pmg_quarantine_spam, pmg_quarantine_virus
│   ├── pmg_clamav.py                    # pmg_clamav
│   ├── pmg_spamassassin.py              # pmg_spamassassin
│   └── pmg_node.py                      # pmg_node_status, pmg_updates, pmg_certificates
├── rulesets/                             # WATO rules (connection params + check params)
│   ├── pmg.py
│   └── pmg_params.py
├── server_side_calls/pmg.py             # wires the ruleset to the special agent
├── graphing/pmg.py                      # metric/graph definitions
└── checkman/                             # manpages (one per check plugin)
```

## Install

```
mkp add pmg-1.0.5.mkp
mkp enable pmg 1.0.5
```

Then create a host for the PMG node and add a rule under
*Setup → Agents → Other integrations → Proxmox Mail Gateway via REST API*
(this MKP's special-agent ruleset). Supply:

- **Host / address** — the PMG node.
- **Username** and **Password** — best referenced from the Checkmk password
  store rather than typed inline, so no plaintext credential lands in the
  rule or the process list.
- **Port** — default `8006`.
- **TLS certificate check** — can be disabled for self-signed certificates.

Create the audit user in PMG under *Configuration → User Management → Users*,
assigning it the **Audit** role (read-only) — the special agent only ever
performs read-only GET calls.

## Verified against

- Checkmk 2.5.0p10 (Enterprise/CRE cmk_addons layout)
- Proxmox Mail Gateway 8.x, REST API on port 8006

## Changelog

- **1.0.5**
  - Adjusted the junk/spam/virus ratio metric colors for better distinction:
    junk ratio now blue, spam ratio green, virus ratio purple (previously
    orange/yellow/red, the latter clashing with the CRIT threshold color).
- **1.0.4**
  - The "Disable TLS certificate verification" checkbox in the connection
    ruleset now shows an inline label ("SSL certificate validation is
    disabled") instead of appearing unlabeled.
  - The junk/spam/virus ratio graph now draws the configured WARN/CRIT
    thresholds as horizontal reference lines.
  - Renamed the misleading "Junk ratio (spam + virus)" metric/graph/parameter
    title to "Junk ratio (PMG-reported)" to avoid confusion with the sum of
    the spam and virus ratios shown alongside it.
- **1.0.3**
  - Initial public release.
