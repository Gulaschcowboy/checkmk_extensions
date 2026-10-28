# SSH daemon crypto algorithms / PQC key exchange

## What it monitors
Checkmk MKP that evaluates the cryptographic algorithms the **OpenSSH daemon**
offers according to its effective configuration (`sshd -T`):

- key exchange algorithms (`KexAlgorithms`)
- ciphers (`Ciphers`)
- MACs (`MACs`)
- host key algorithms (`HostKeyAlgorithms`)
- accepted public key algorithms (`PubkeyAcceptedAlgorithms`, older
  `PubkeyAcceptedKeyTypes` is understood as well)

The service **SSH daemon crypto** reports:

- whether a **post-quantum (PQC) hybrid key exchange** is offered, e.g.
  `mlkem768x25519-sha256` or `sntrup761x25519-sha512@openssh.com`
  (WARN if not, configurable),
- optionally, whether classic (non-PQC) key exchange is still offered in
  addition (OK by default, set WARN/CRIT to enforce a PQC-only setup),
- **disallowed algorithms** per category, configured as shell wildcard
  patterns (e.g. `ssh-rsa`, `*-cbc`, `hmac-sha1*`),
- optionally **required algorithms** per category (e.g. `ssh-ed25519`,
  `*-gcm@openssh.com`): every pattern must match at least one offered
  algorithm. Nothing is required by default.

The defaults only flag broken legacy algorithms that no current OpenSSH
enables by default (SHA-1 DH groups, CBC/RC4/3DES/Blowfish/CAST ciphers,
MD5/truncated SHA-1/RIPEMD MACs, DSA and SHA-1 RSA signatures), so a stock
modern sshd is OK apart from the PQC result. The OpenSSH version and all
algorithm lists are shown in the service details.

Notes:

- SSH picks the first algorithm of the *client's* list that the server
  supports, so the order of the server list is irrelevant and not evaluated.
  The check shows what the server offers, not what a given client negotiates.
- `Match` blocks in `sshd_config` are not evaluated.
- The built-in *SSH daemon configuration* service is not touched; both
  services coexist.

## Requirements

- Checkmk 2.3.0 or newer (uses `cmk.agent_based.v2`, `cmk.rulesets.v1`).
- OpenSSH server on the monitored host; the agent plug-in runs as root
  (`sshd -T` needs to read the host keys). It is a plain POSIX shell script.
- The Agent Bakery (bakery plug-in) requires a **commercial edition**. The
  check itself works on all editions — deploy the agent plug-in manually
  there.

## Installation

```bash
mkp add sshd_crypto-0.9.0.mkp
mkp enable sshd_crypto 0.9.0
```

### Deploy the agent plug-in

**With the bakery (recommended):** create a rule under
*Setup → Agents → Agent rules → SSH daemon crypto algorithms (Linux)*, bake
and sign the agent, and roll it out. The sshd configuration rarely changes,
so asynchronous execution (e.g. every hour) is fine.

**Manually (any edition):**

```bash
# on the monitored host
cp sshd_crypto /usr/lib/check_mk_agent/plugins/sshd_crypto
chmod +x /usr/lib/check_mk_agent/plugins/sshd_crypto
# test:
/usr/lib/check_mk_agent/plugins/sshd_crypto
```

On hosts without `sshd` the plug-in prints nothing, so no service is
discovered there.

### Parameters

*Setup → Services → Service monitoring rules → SSH daemon crypto algorithms*:
PQC algorithm patterns, state if no PQC key exchange is offered, state if
classic key exchange is offered in addition, state for disallowed algorithms
and the disallowed pattern lists per category, state for missing required
algorithms and the required pattern lists per category.

## Changelog

- **0.9.0** — Initial release.

## License

GPLv2.
