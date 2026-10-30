#!/bin/bash
# Exercise openssl pkeyutl -encap/-decap against an oqsprovider KEM.
# Requires OpenSSL >= 3.4 and a build with OQS_KEM_ENCODERS=ON plus a KEM
# that has a registered OID (file-based keys). Skips cleanly (exit 0) when
# those prerequisites are missing.
#
# Optional arg: KEM algorithm name (default: first usable oqsprovider KEM).

set -e

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

# Parse OpenSSL major.minor from "OpenSSL 3.4.0 ..." / "OpenSSL 3.6.5 ..."
ossl_ver=$("$OPENSSL_APP" version | awk '{print $2}')
ossl_major=${ossl_ver%%.*}
ossl_rest=${ossl_ver#*.}
ossl_minor=${ossl_rest%%.*}
ossl_minor=${ossl_minor%%[^0-9]*}

if [ -z "$ossl_major" ] || [ -z "$ossl_minor" ]; then
    echo "Could not parse OpenSSL version from: $ossl_ver — skipping pkeyutl encap/decap test."
    exit 0
fi

if [ "$ossl_major" -lt 3 ] || { [ "$ossl_major" -eq 3 ] && [ "$ossl_minor" -lt 4 ]; }; then
    echo "OpenSSL $ossl_ver < 3.4 — skipping pkeyutl -encap/-decap test."
    exit 0
fi

mkdir -p tmp
WORKDIR=$(mktemp -d tmp/kem-encap.XXXXXX)
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

alg_usable() {
    # Must be listed under oqsprovider and support PEM genpkey (needs OID + encoders).
    # Listing @ oqsprovider already excludes pure ML-KEM names that OpenSSL >= 3.5
    # serves via the default provider (oqsprovider cedes those at init).
    "$OPENSSL_APP" list -kem-algorithms 2>/dev/null | grep oqsprovider | grep -q "$1" || return 1
    "$OPENSSL_APP" genpkey -algorithm "$1" -out "$WORKDIR/probe.pem" 2>/dev/null || return 1
    rm -f "$WORKDIR/probe.pem"
    return 0
}

pick_alg() {
    if [ -n "$1" ]; then
        echo "$1"
        return
    fi
    # First oqsprovider KEM that can write a PEM key (no preferred-name heuristics).
    "$OPENSSL_APP" list -kem-algorithms 2>/dev/null \
        | grep oqsprovider \
        | sed -e 's/^[[:space:]]*{[^}]*,[[:space:]]*\([^,}]*[^,} ]\)[[:space:]]*}[[:space:]]*@.*/\1/' \
              -e 's/[[:space:]]*@[[:space:]].*//g' \
              -e 's/^[[:space:]]*//' \
        | while read -r name; do
            [ -z "$name" ] && continue
            if alg_usable "$name"; then
                echo "$name"
                break
            fi
        done
}

ALG=$(pick_alg "$1")
if [ -z "$ALG" ]; then
    echo "No usable oqsprovider KEM for file-based genpkey (need OQS_KEM_ENCODERS=ON and a registered OID?). Skipping pkeyutl encap/decap test."
    exit 0
fi

echo "Testing pkeyutl -encap/-decap for KEM algorithm: $ALG (OpenSSL $ossl_ver)"

"$OPENSSL_APP" genpkey -algorithm "$ALG" -out "$WORKDIR/priv.pem"
"$OPENSSL_APP" pkey -in "$WORKDIR/priv.pem" -pubout -out "$WORKDIR/pub.pem"

"$OPENSSL_APP" pkeyutl -encap -pubin -inkey "$WORKDIR/pub.pem" \
    -out "$WORKDIR/ct.bin" -secret "$WORKDIR/ss_enc.bin"
"$OPENSSL_APP" pkeyutl -decap -inkey "$WORKDIR/priv.pem" \
    -in "$WORKDIR/ct.bin" -out "$WORKDIR/ss_dec.bin"

if ! cmp -s "$WORKDIR/ss_enc.bin" "$WORKDIR/ss_dec.bin"; then
    echo "FAIL: encapsulated and decapsulated secrets differ for $ALG"
    exit 1
fi

echo "PASS: pkeyutl encap/decap secrets match for $ALG"
