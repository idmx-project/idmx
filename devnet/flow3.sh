#!/usr/bin/env bash
# Flow 3: the conformance suite against both receivers, each probed by the
# other domain's signing identity. Expects a running devnet (./up.sh).
set -euo pipefail

engine=${CONTAINER_ENGINE:-podman}
failures=0

conformance() { # probing container, its domain, origin, recipient
    echo "== $3 (signed by $2, delivering to $4)"
    if ! "$engine" exec "$1" idmx-conformance "$3" \
        --ca /etc/idmx/ca.pem --key /etc/idmx/signing.pem \
        --keyid "s1._idmxkey.$2" --recipient "$4"; then
        failures=$((failures + 1))
    fi
    echo
}

# domain-b listens on 8443 (explicit port in @authority), domain-a on 443
# (default port, no port in @authority).
conformance idmx-domain-a domain-a.test https://idmx.domain-b.test:8443 bob@domain-b.test
conformance idmx-domain-b domain-b.test https://idmx.domain-a.test alice@domain-a.test

if [[ $failures -eq 0 ]]; then
    echo "flow 3: both receivers conform"
else
    echo "flow 3: $failures receiver(s) violate a MUST"
    exit 1
fi
