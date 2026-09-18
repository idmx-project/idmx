#!/usr/bin/env bash
# Flow 1: modern -> modern. Expects a running devnet (./up.sh).
set -euo pipefail

engine=${CONTAINER_ENGINE:-podman}
failures=0

check() { # description, command...
    local description=$1
    shift
    if "$@" >/tmp/idmx-flow1.out 2>&1; then
        echo "PASS  $description"
    else
        echo "FAIL  $description"
        sed 's/^/      /' /tmp/idmx-flow1.out
        failures=$((failures + 1))
    fi
}

send() { # container, from, to, extra idmx args...
    local container=$1 from=$2 to=$3
    shift 3
    printf 'From: %s\r\nTo: %s\r\nSubject: devnet flow 1\r\n\r\nHello over IDMX\r\n' "$from" "$to" |
        "$engine" exec -i "$container" idmx send \
            --key /etc/idmx/signing.pem --keyid "${KEYID:-s1._idmxkey.${from#*@}}" \
            --ca /etc/idmx/ca.pem --from "$from" --to "$to" "$@"
}

refused_with() { # pattern, then send arguments: delivery must fail for that reason
    local pattern=$1 output
    shift
    if output=$(send "$@" 2>&1); then
        echo "delivery unexpectedly succeeded"
        return 1
    fi
    echo "$output"
    grep -q -- "$pattern" <<<"$output"
}

stored() { # container, user, pattern: some delivered message contains pattern
    "$engine" exec "$1" sh -c "grep -rqs -- '$3' /var/lib/idmxd/mail/$2/new"
}

wait_for_discovery() {
    for _ in $(seq 1 30); do
        if "$engine" exec idmx-domain-a idmx discover domain-b.test 2>/dev/null | grep -q https; then
            return 0
        fi
        sleep 1
    done
    return 1
}

check "domain-b.test is discoverable from domain-a" wait_for_discovery
check "discovery honors the SVCB port parameter" \
    "$engine" exec idmx-domain-a sh -c "idmx discover domain-b.test | grep -qx 'https://idmx.domain-b.test:8443 (h2)'"
check "sender key of domain-a.test is published" \
    "$engine" exec idmx-domain-b sh -c "idmx key s1._idmxkey.domain-a.test | grep -q '^v=IDMX1; k=ed25519; p='"

check "alice@domain-a.test -> bob@domain-b.test is accepted" \
    send idmx-domain-a alice@domain-a.test bob@domain-b.test --idempotency-key flow1-a-to-b
check "bob's maildir has the message with idmx=pass for domain-a.test" \
    stored idmx-domain-b bob "idmx=pass header.d=domain-a.test header.s=s1"
check "retry with the same idempotency key is accepted again" \
    send idmx-domain-a alice@domain-a.test bob@domain-b.test --idempotency-key flow1-a-to-b
check "the retry did not deliver a second copy" \
    "$engine" exec idmx-domain-b sh -c '[ "$(ls /var/lib/idmxd/mail/bob/new | wc -l)" -eq 1 ]'

check "bob@domain-b.test -> alice@domain-a.test is accepted (default port 443)" \
    send idmx-domain-b bob@domain-b.test alice@domain-a.test
check "alice's maildir has the message with idmx=pass for domain-b.test" \
    stored idmx-domain-a alice "idmx=pass header.d=domain-b.test header.s=s1"

check "unknown recipient is refused" \
    refused_with recipient_not_found idmx-domain-a alice@domain-a.test nobody@domain-b.test
forged_sender() {
    KEYID=s1._idmxkey.domain-a.test refused_with "not in the signing domain" \
        idmx-domain-a mallory@domain-b.test bob@domain-b.test
}
check "sender outside the signing domain is refused" forged_sender

echo
if [[ $failures -eq 0 ]]; then
    echo "flow 1: all checks passed"
else
    echo "flow 1: $failures check(s) failed"
    exit 1
fi
