#!/bin/bash

set -e 

# Use newly built oqsprovider to test interop with external sites

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_MODULES" ]; then
    echo "Warning: OPENSSL_MODULES env var not set."
fi

# Set OSX DYLD_LIBRARY_PATH if not already externally set
if [ -z "$DYLD_LIBRARY_PATH" ]; then
    export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH
fi

# Disable this test if HTTP_PROXY or HTTPS_PROXY is set
if [ -v HTTP_PROXY ] || [ -v HTTPS_PROXY ]; then
    echo "HTTP(S) proxy vars set. Disabling interop test."
    exit 0
fi

echo " Cloudflare:"
export OQS_CODEPOINT_X25519_KYBER512=65072
(echo -e "GET /cdn-cgi/trace HTTP/1.1\nHost: cloudflare.com\n\n"; sleep 1; echo $'\cc') | $OPENSSL_APP s_client -connect pq.cloudflareresearch.com:443 -groups x25519_kyber768 -servername cloudflare.com -ign_eof 2>/dev/null | grep kex=X25519Kyber768Draft00
(echo -e "GET /cdn-cgi/trace HTTP/1.1\nHost: cloudflare.com\n\n"; sleep 1; echo $'\cc') | $OPENSSL_APP s_client -connect pq.cloudflareresearch.com:443 -groups x25519_kyber512 -servername cloudflare.com -ign_eof 2>/dev/null | grep kex=X25519Kyber512Draft00


