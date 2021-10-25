#!/bin/bash

# Use newly built oqsprovider to generate certs for alg $1
# Assumes .local to contain openssl(3) and oqsprovider to be in _build folder

# uncomment to see what's happening:
# set -x

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

rm -rf tmp
mkdir tmp
export OPENSSL_MODULES=_build/oqsprov
export LD_LIBRARY_PATH=.local/lib64
.local/bin/openssl req -x509 -new -newkey $1 -keyout tmp/$1_CA.key -out tmp/$1_CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config openssl/apps/openssl.cnf -provider oqsprovider -provider default && \
.local/bin/openssl genpkey -algorithm $1 -out tmp/$1_srv.key -provider oqsprovider -provider default && \
.local/bin/openssl req -new -newkey $1 -keyout tmp/$1_srv.key -out tmp/$1_srv.csr -nodes -subj "/CN=oqstest server" -config openssl/apps/openssl.cnf -provider oqsprovider -provider default && \
.local/bin/openssl x509 -req -in tmp/$1_srv.csr -out tmp/$1_srv.crt -CA tmp/$1_CA.crt -CAkey tmp/$1_CA.key -CAcreateserial -days 365 -provider oqsprovider -provider default && \
.local/bin/openssl verify -provider oqsprovider -provider default -CAfile tmp/$1_CA.crt tmp/$1_srv.crt 

#fails:
#.local/bin/openssl verify -CAfile tmp/$1_CA.crt tmp/$1_srv.crt -provider oqsprovider -provider default

