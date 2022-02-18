#!/bin/bash

# Use newly built oqsprovider to generate CMS signed files for alg $1
# Assumes .local to contain openssl(3) and oqsprovider to be in _build folder
# Assumed oqsprovider-certgen.sh to have run before for same algorithm

# uncomment to see what's happening:
# set -x

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

# Assumes certgen has been run before: Quick check

if [ -f tmp/signedfile.cms ]; then
    export OPENSSL_MODULES=_build/oqsprov
    export LD_LIBRARY_PATH=.local/lib64
    .local/bin/openssl cms -verify -CAfile tmp/$1_CA.crt -inform pem -in tmp/signedfile.cms -crlfeol -out tmp/signeddatafile -provider oqsprovider -provider default
    diff tmp/signeddatafile tmp/inputfile
    #rm tmp/signeddatafile tmp/signedfile.cms
else
   echo "File tmp/signedfile.cms not found. Did CMS sign run before? Exiting."
   exit -1
fi

