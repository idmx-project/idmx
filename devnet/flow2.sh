#!/usr/bin/env bash
# Flow 2: SMTP fallback. Expects a running devnet (./up.sh).
#
# The sender is idmx-mta-a: `idmx queue` plus Postfix as outbound MTA of
# domain-a.test. idmx-legacy is the SMTP-only MX of legacy.test and also the
# SMTP MX of domain-b.test. Stops and restarts idmx-domain-b.
set -euo pipefail

engine=${CONTAINER_ENGINE:-podman}
failures=0
spool=/var/spool/idmx
# Seconds; the specification's values are 60 and 7200.
first_delay=2 fallback_window=10

check() { # description, command...
    local description=$1
    shift
    if "$@" >/tmp/idmx-flow2.out 2>&1; then
        echo "PASS  $description"
    else
        echo "FAIL  $description"
        sed 's/^/      /' /tmp/idmx-flow2.out
        failures=$((failures + 1))
    fi
}

queue() { # to, subject
    printf 'From: alice@domain-a.test\r\nTo: %s\r\nSubject: %s\r\n\r\nHello\r\n' "$1" "$2" |
        "$engine" exec -i idmx-mta-a idmx queue add --spool "$spool" \
            --from alice@domain-a.test --to "$1"
}

run() {
    "$engine" exec idmx-mta-a idmx queue run --spool "$spool" \
        --key /etc/idmx/signing.pem --keyid s1._idmxkey.domain-a.test --ca /etc/idmx/ca.pem \
        --first-delay "$first_delay" --fallback-window "$fallback_window"
}

run_says() { # pattern: one queue run prints a line matching pattern
    local output
    output=$(run 2>&1) || true
    echo "$output"
    grep -q -- "$1" <<<"$output"
}

smtp_delivered() { # mailbox dir below /var/mail/vhosts, pattern; Postfix delivers asynchronously
    for _ in $(seq 1 30); do
        if "$engine" exec idmx-legacy sh -c "grep -rqs -- '$2' /var/mail/vhosts/$1"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

not_smtp_delivered() { # mailbox dir, pattern
    ! "$engine" exec idmx-legacy sh -c "grep -rqs -- '$2' /var/mail/vhosts/$1"
}

wait_for_dns() {
    for _ in $(seq 1 30); do
        if "$engine" exec idmx-mta-a idmx discover domain-b.test 2>/dev/null | grep -q https; then
            return 0
        fi
        sleep 1
    done
    return 1
}

"$engine" start idmx-domain-b >/dev/null
# Start clean so that the flow can be repeated.
"$engine" exec idmx-mta-a rm -rf "$spool"
"$engine" exec idmx-legacy sh -c 'rm -rf /var/mail/vhosts/*'
check "DNS is up" wait_for_dns

echo "-- legacy.test does not advertise IDMX"
check "legacy.test has no IDMX record" \
    "$engine" exec idmx-mta-a sh -c "idmx discover legacy.test | grep -q 'use SMTP'"
check "message to bob@legacy.test is queued" queue bob@legacy.test flow2-legacy
check "queue run hands it to SMTP at once" run_says "bob@legacy.test: handed to SMTP"
check "bob@legacy.test received it over SMTP from mail.domain-a.test" \
    smtp_delivered legacy.test/bob "flow2-legacy"
check "... with Postfix's trace header" \
    smtp_delivered legacy.test/bob "from mail.domain-a.test"

echo "-- an IDMX rejection never falls back"
check "message to nobody@domain-b.test is queued" queue nobody@domain-b.test flow2-rejected
check "queue run fails it permanently" run_says "nobody@domain-b.test: failed: .*recipient_not_found"
check "nothing went to SMTP" not_smtp_delivered domain-b.test "flow2-rejected"
check "next queue run delivers the bounce to alice over IDMX" \
    run_says "alice@domain-a.test: accepted over IDMX"
check "alice's maildir has the DSN for nobody@domain-b.test" \
    "$engine" exec idmx-domain-a sh -c \
    "grep -rqs 'Final-Recipient: rfc822; nobody@domain-b.test' /var/lib/idmxd/mail/alice/new"
check "queue is empty" run_says "^0 job(s) still queued"

echo "-- pinned domain, endpoint down: retry IDMX, then SMTP after the window"
check "message to bob@domain-b.test is queued" queue bob@domain-b.test flow2-idmx
check "queue run delivers it over IDMX" run_says "bob@domain-b.test: accepted over IDMX"
check "domain-b.test is now pinned" \
    "$engine" exec idmx-mta-a grep -q '"domain-b.test"' "$spool/pins.json"

echo "-- pinned domain, SVCB record stripped from DNS: stay on IDMX"
zone=$(dirname "$0")/generated/dns/domain-b.test.zone
original=$(<"$zone")
publish() { # zone text: CoreDNS reloads the zone when the SOA serial changes
    sed "s/IN SOA\(.*\) [0-9]* 3600 600/IN SOA\1 $(date +%s) 3600 600/" <<<"$1" >"$zone"
}
discovery_says() { # pattern
    for _ in $(seq 1 30); do
        if "$engine" exec idmx-mta-a idmx discover domain-b.test 2>&1 | grep -q -- "$1"; then
            return 0
        fi
        sleep 1
    done
    return 1
}
publish "$(grep -v '^_idmx ' <<<"$original")"
check "domain-b.test no longer advertises IDMX" discovery_says "use SMTP"
check "message to bob@domain-b.test is queued" queue bob@domain-b.test flow2-pinned
check "queue run still delivers it over IDMX (pinned endpoint)" \
    run_says "bob@domain-b.test: accepted over IDMX"
check "it never went to SMTP" not_smtp_delivered domain-b.test/bob "flow2-pinned"
sleep 1 # a new serial needs a new second
publish "$original"
check "domain-b.test advertises IDMX again" discovery_says https

"$engine" stop idmx-domain-b >/dev/null
check "second message to bob@domain-b.test is queued" queue bob@domain-b.test flow2-fallback
check "queue run inside the window schedules an IDMX retry" run_says "bob@domain-b.test: retry in"
check "nothing went to SMTP yet" not_smtp_delivered domain-b.test/bob "flow2-fallback"
# An attempt at a just-stopped container can take a connect timeout (30 s),
# so there is no reliable second attempt inside a short window.
sleep "$fallback_window"
check "queue run after the window hands it to SMTP" run_says "bob@domain-b.test: handed to SMTP"
check "bob@domain-b.test received it over SMTP" smtp_delivered domain-b.test/bob "flow2-fallback"
check "the IDMX-delivered message never went to SMTP" not_smtp_delivered domain-b.test/bob "flow2-idmx"
"$engine" start idmx-domain-b >/dev/null

echo
if [[ $failures -eq 0 ]]; then
    echo "flow 2: all checks passed"
else
    echo "flow 2: $failures check(s) failed"
    exit 1
fi
