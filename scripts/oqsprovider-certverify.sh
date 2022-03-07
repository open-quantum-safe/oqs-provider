#!/bin/bash

# Use newly built oqsprovider to generate certs for alg $1

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_APP" ]; then
    echo "OPENSSL_APP env var not set. Exiting."
    exit 1
fi

if [ -z "$OPENSSL_MODULES" ]; then
    echo "OPENSSL_MODULES env var not set. Exiting."
    exit 1
fi

if [ -z "$LD_LIBRARY_PATH" ]; then
    echo "LD_LIBRARY_PATH env var not set. Exiting."
    exit 1
fi

$OPENSSL_APP verify -provider oqsprovider -provider default -CAfile tmp/$1_CA.crt tmp/$1_srv.crt 

