# LinOTP (via REST API)

Checkmk special agent that monitors a LinOTP two-factor authentication
server entirely over HTTPS, using LinOTP's own JSONRPC admin/monitoring API
-- no agent installation on the LinOTP server itself needed.

<img width="1338" height="289" alt="grafik" src="https://github.com/user-attachments/assets/f1e7d5d3-107b-47c5-9d03-a8b51eaaf64b" />


## What it does

The agent logs in against `/admin/login` (JWT cookie auth) with a LinOTP
admin user/password (a read-only admin account is sufficient), then reads:

- `/monitoring/tokens` -- token counts per realm
- `/monitoring/activeUsers` and `/monitoring/userinfo` -- recently active
  and configured user counts per resolver, per realm
- `/monitoring/storageEncryption` -- whether token/config secrets are
  encrypted at rest
- `/monitoring/config` -- config sync status and realm/resolver/policy
  counts
- `/monitoring/license` and `/system/isSupportValid` -- license/support
  status, including LinOTP's own grace-limit message when the licensed
  token count is reached or exceeded
- `/system/getRealms` -- the list of configured realms

For every LinOTP realm, the special agent creates these services directly
on the host it runs on (no piggyback hosts):

- **LinOTP Tokens `<realm>`**: total tokens and total users with at least
  one token; optional upper/lower levels on both (off by default), e.g.
  for an early warning before a license limit is reached or to notice
  unexpected bulk token revocation.
- **LinOTP Resolver `<realm> / <resolver>`**: one service per resolver
  (LDAP/SQL/file user backend) in that realm, reporting configured and
  recently-active user counts. A resolver reporting fewer configured
  users than expected (default: below 1) usually means its backend is
  unreachable; upper levels (e.g. for an unexpected bulk user import)
  are configurable but off by default.

Additionally, also on that same host:

- **LinOTP Source**: the special agent's own run health (login, primary
  query, duration).
- **LinOTP License**: license/support status and token count trending.
- **LinOTP Storage Encryption**: CRIT if encryption is inactive.
- **LinOTP Config Sync**: config sync status across cluster nodes
  (mainly useful for multi-node/HA installations).

Only read-only endpoints are ever called; nothing under `/admin/init`,
`/admin/remove`, `/system/setConfig` etc.

## Requirements

- LinOTP with the "monitoring controller" enabled.
- A LinOTP admin account; a read-only admin role is sufficient for
  monitoring.
- Network access from the Checkmk server to LinOTP over HTTPS.

## Configuration

Setup -> Agents -> Other integrations -> "LinOTP (via REST API)". Assign
the rule to a host(s) representing the LinOTP instance(s). The password can be
stored in the Checkmk password store.

## Changelog

- **1.0.0** -- Initial release. Token counts and per-resolver user counts
  per realm as plain services on the queried host (with optional
  upper/lower levels), license/support status including LinOTP's
  grace-limit message, storage encryption and config sync status, and
  the special agent's own run health.

## Verified against

- Checkmk 2.5.0 and 3.0.0 (daily build), `cmk_addons_plugins` layout.
- A production LinOTP 3.2.6 instance
