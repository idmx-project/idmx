#!/usr/bin/env bash
# Generates everything secret or derived for the devnet into devnet/generated/:
# a throw-away CA, server certificates, sender signing keys, DNS zones, and
# idmxd configs. Idempotent: existing keys are kept.
set -euo pipefail

cd "$(dirname "$0")"
out=generated
mkdir -p "$out/dns"

if [[ ! -f $out/ca.key ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$out/ca.key" -out "$out/ca.pem" -days 365 \
        -subj "/CN=IDMX devnet CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

render() { # template, then KEY=VALUE pairs
    local text
    text=$(<"templates/$1")
    shift
    for pair in "$@"; do
        text=${text//@${pair%%=*}@/${pair#*=}}
    done
    printf '%s\n' "$text"
}

domain() { # name, domain, ip, port, user
    local name=$1 domain=$2 ip=$3 port=$4 user=$5
    local dir=$out/$name host=idmx.$2
    mkdir -p "$dir"

    if [[ ! -f $dir/key.pem ]]; then
        # rustls-platform-verifier insists on the serverAuth EKU.
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$dir/key.pem" -out "$dir/server.csr" -subj "/CN=$host" 2>/dev/null
        openssl x509 -req -in "$dir/server.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" \
            -CAcreateserial -days 365 -out "$dir/cert.pem" \
            -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host") 2>/dev/null
        rm "$dir/server.csr"
    fi
    [[ -f $dir/signing.pem ]] || openssl genpkey -algorithm ed25519 -out "$dir/signing.pem"
    cp "$out/ca.pem" "$dir/ca.pem"
    chmod 644 "$dir"/*.pem

    # The raw Ed25519 public key is the last 32 bytes of the DER SubjectPublicKeyInfo.
    local public_key authority=$host svcb_params=""
    public_key=$(openssl pkey -in "$dir/signing.pem" -pubout -outform DER | tail -c 32 | base64)
    if [[ $port != 443 ]]; then
        authority=$host:$port
        svcb_params="port=$port"
    fi

    render zone "DOMAIN=$domain" "IP=$ip" "SVCB_PARAMS=$svcb_params" "PUBLIC_KEY=$public_key" \
        >"$out/dns/$domain.zone"
    render idmxd.toml "DOMAIN=$domain" "AUTHORITY=$authority" "PORT=$port" "USER=$user" \
        >"$dir/idmxd.toml"
}

domain domain-a domain-a.test 10.89.53.11 443 alice
domain domain-b domain-b.test 10.89.53.12 8443 bob
# SMTP only: MX, no _idmx record.
cp templates/zone-legacy "$out/dns/legacy.test.zone"
cp templates/Corefile "$out/dns/Corefile"
echo "devnet material generated in devnet/$out"
