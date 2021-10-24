#!/bin/bash

# Use newly built oqsprovider to generate certs for alg $1
# Assumes .local to contain openssl(3) and oqsprovider to be in _build folder

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

export OPENSSL_MODULES=_build/oqsprov
export LD_LIBRARY_PATH=.local/lib64


.local/bin/openssl verify -provider oqsprovider -provider default -CAfile tmp/$1_CA.crt tmp/$1_srv.crt 

