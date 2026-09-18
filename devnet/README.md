# devnet

A local IDMX network in containers: one DNS server, two "modern" mail
domains that deliver to each other over IDMX, and an SMTP-only legacy domain
for the fallback path. Works with **rootless podman**
(default) or docker.

| Container | Role | Address |
|---|---|---|
| `idmx-dns` | CoreDNS, authoritative for `domain-a.test`, `domain-b.test` (SVCB + key records + MX) and `legacy.test` (MX only) | 10.89.53.2 |
| `idmx-domain-a` | `idmxd` for `domain-a.test`, port 443, mailbox `alice` | 10.89.53.11 |
| `idmx-domain-b` | `idmxd` for `domain-b.test`, port 8443 (advertised via SVCB `port=`), mailbox `bob` | 10.89.53.12 |
| `idmx-mta-a` | Outbound MTA of `domain-a.test`: `idmx queue` (spool in `/var/spool/idmx`) plus Postfix for the SMTP hand-off | 10.89.53.21 |
| `idmx-legacy` | Postfix, `mx.legacy.test`: MX of `legacy.test` and SMTP MX of the modern domains; Maildirs in `/var/mail/vhosts/<domain>/<user>/` | 10.89.53.30 |

Each domain container also has the `idmx` CLI and its domain's signing key, so
it doubles as that domain's sender.

## Usage

```bash
./devnet/up.sh        # generate keys/certs/zones, build image, start
./devnet/flow1.sh     # flow 1: modern -> modern, with checks
./devnet/flow2.sh     # flow 2: SMTP fallback, with checks (stops/starts idmx-domain-b)
./devnet/down.sh      # stop and remove the network
```

Set `CONTAINER_ENGINE=docker` to use docker instead of podman. `podman compose`
needs a compose provider (`docker-compose` or `podman-compose`).

Poke around:

```bash
podman exec idmx-domain-a idmx discover domain-b.test
podman exec idmx-domain-b idmx key s1._idmxkey.domain-a.test
podman exec idmx-domain-b sh -c 'cat /var/lib/idmxd/mail/bob/new/*'
podman logs idmx-domain-b
podman exec idmx-mta-a cat /var/spool/idmx/pins.json
podman exec idmx-legacy sh -c 'cat /var/mail/vhosts/legacy.test/bob/new/*'
podman logs idmx-mta-a        # Postfix log of the sending side
```

## How it fits together

- `setup.sh` writes everything derived or secret to `devnet/generated/`
  (git-ignored): a throw-away CA, server certificates (with the `serverAuth`
  EKU, which the TLS verifier requires), one Ed25519 signing key per domain,
  the DNS zones containing the matching public keys, and the `idmxd` configs.
- The network is created with `--disable-dns`, so the containers' only
  resolver is CoreDNS and SVCB/TXT lookups take the same path as in production.
- Nothing is published to the host; all traffic stays on the container network.

## Flow 2

`flow2.sh` covers the three sender-side rules of `spec/errors.md` §3:

1. `legacy.test` has no `_idmx` record and no pin: `idmx queue run` hands the
   message to Postfix at once, which delivers it by MX lookup.
2. An IDMX rejection (`recipient_not_found`) fails the job and never reaches
   SMTP.
3. `domain-b.test` is pinned by a successful IDMX delivery, then its endpoint
   is stopped: the job is retried over IDMX and goes to SMTP only after the
   fallback window (shortened to seconds with `--fallback-window`).
