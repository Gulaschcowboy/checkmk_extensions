# DNSSEC health — Checkmk Special Agent

Checkmk MKP that monitors the **DNSSEC status of arbitrary domains**. It runs entirely from the Checkmk site — no agent needs to be
deployed on the monitored host, and it has **no Python dependencies** (pure
standard library, no `dnspython`).

Every configured domain is checked **against every configured DNS server**, so
one service `DNSSEC <domain> via <resolver>` is created per domain/resolver
combination, reporting:

| Aspect      | Meaning                                                                 |
|-------------|-------------------------------------------------------------------------|
| `signed`    | The domain publishes `DNSKEY` records (i.e. it is DNSSEC-signed)        |
| `validated` | That specific resolver set the `AD` (Authenticated Data) bit            |

> Because each resolver is queried in isolation (no failover between servers),
> the `validated` result tells you whether **that particular DNS server**
> performs DNSSEC validation — not just whether the domain is signed. This makes
> a non-validating or misconfigured resolver visible as its own failing service.

## How it works

The special agent (`libexec/agent_dnssec_health`) builds raw DNS queries with
`struct`, sets the `RD` and `AD` flags, and asks the resolver for:

* a `DNSKEY` query — presence of answers ⇒ the domain is signed;
* an `SOA` query — the `AD` bit in the reply ⇒ the resolver validated it.

UDP is used first with an automatic TCP fallback on truncation (`TC` bit),
plus retries and IPv6 support. `NXDOMAIN` is treated as "not signed";
`SERVFAIL` (typical for a broken signature at a validating resolver) is surfaced
as an `error`.

## Layout

```
cmk_addons_plugins/dnssec_health/
├── libexec/agent_dnssec_health                     # special agent (stdlib DNS client)
├── agent_based/dnssec_health.py                    # AgentSection + CheckPlugin
├── rulesets/
│   ├── special_agent_dnssec_health.py              # WATO: domains / nameservers / timeout
│   └── check_parameters_dnssec_health.py           # WATO: state mapping
├── server_side_calls/dnssec_health.py              # wires the ruleset to the agent
└── checkman/dnssec_health                          # manpage
```

## Setup

1. Install the package: `mkp add dnssec_health-1.1.1.mkp && mkp enable dnssec_health 1.1.1`.
2. In the GUI: **Setup › Agents › Other integrations › DNSSEC status**.
3. Add the domains to check. Optionally pin the recursive DNS servers to use
   (default: the resolvers from the Checkmk server's `/etc/resolv.conf`) and the
   per-query timeout (default 5 s).
4. Assign the rule to a host, run service discovery, and activate changes.

## Check parameters

The rule **DNSSEC status** (Setup › Service monitoring rules) controls the
service state for the two failure modes (both default to **WARN**):

* **not DNSSEC-signed** — the domain has no `DNSKEY` records;
* **signed but not validated** — `DNSKEY` present but the resolver did not set
  the `AD` bit (usually a non-validating resolver, or a validation failure).

## Changelog

- **1.1.1** — Make description compatible with Checkmk Exchange.

## Compatibility

* Checkmk **2.5.0** or newer (agent-based API v2, rulesets `form_specs` v1,
  server-side-calls v1).

## License

GNU General Public License v2.
