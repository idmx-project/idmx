# devnet

A local IDMX network in containers: one DNS server and two "modern" mail
domains that deliver to each other over IDMX. Works with **rootless podman**
(default) or docker.

| Container | Role | Address |
|---|---|---|
| `idmx-dns` | CoreDNS, authoritative for `domain-a.test` and `domain-b.test` (SVCB + key records) | 10.89.53.2 |
| `idmx-domain-a` | `idmxd` for `domain-a.test`, port 443, mailbox `alice` | 10.89.53.11 |
| `idmx-domain-b` | `idmxd` for `domain-b.test`, port 8443 (advertised via SVCB `port=`), mailbox `bob` | 10.89.53.12 |

Each domain container also has the `idmx` CLI and its domain's signing key, so
it doubles as that domain's sender.

## Usage

```bash
./devnet/up.sh        # generate keys/certs/zones, build image, start
./devnet/flow1.sh     # flow 1: modern -> modern, with checks
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
```

## How it fits together

- `setup.sh` writes everything derived or secret to `devnet/generated/`
  (git-ignored): a throw-away CA, server certificates (with the `serverAuth`
  EKU, which the TLS verifier requires), one Ed25519 signing key per domain,
  the DNS zones containing the matching public keys, and the `idmxd` configs.
- The network is created with `--disable-dns`, so the containers' only
  resolver is CoreDNS and SVCB/TXT lookups take the same path as in production.
- Nothing is published to the host; all traffic stays on the container network.

## Not here yet

Flow 2 (SMTP fallback): `legacy.test`, Postfix, and the sender queue with
retries and pinning.
