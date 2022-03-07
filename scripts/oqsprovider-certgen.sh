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

rm -rf tmp
mkdir tmp
$OPENSSL_APP req -x509 -new -newkey $1 -keyout tmp/$1_CA.key -out tmp/$1_CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config $OPENSSL_APP.cnf -provider oqsprovider -provider default && \
$OPENSSL_APP genpkey -algorithm $1 -out tmp/$1_srv.key -provider oqsprovider -provider default && \
$OPENSSL_APP req -new -newkey $1 -keyout tmp/$1_srv.key -out tmp/$1_srv.csr -nodes -subj "/CN=oqstest server" -config $OPENSSL_APP.cnf -provider oqsprovider -provider default && \
$OPENSSL_APP x509 -req -in tmp/$1_srv.csr -out tmp/$1_srv.crt -CA tmp/$1_CA.crt -CAkey tmp/$1_CA.key -CAcreateserial -days 365 -provider oqsprovider -provider default && \
$OPENSSL_APP verify -provider oqsprovider -provider default -CAfile tmp/$1_CA.crt tmp/$1_srv.crt

#fails:
#$OPENSSL_APP verify -CAfile tmp/$1_CA.crt tmp/$1_srv.crt -provider oqsprovider -provider default

