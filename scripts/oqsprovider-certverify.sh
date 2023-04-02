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

# check that CSR can be output OK

$OPENSSL_APP req -text -in tmp/$1_srv.csr -noout -provider oqsprovider -provider default 2>&1 | grep Error
if [ $? -eq 0 ]; then
    echo "Couldn't print CSR correctly. Exiting."
    exit 1
fi

$OPENSSL_APP verify -provider oqsprovider -provider default -CAfile tmp/$1_CA.crt tmp/$1_srv.crt 

