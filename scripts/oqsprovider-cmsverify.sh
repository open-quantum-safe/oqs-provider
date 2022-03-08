#!/bin/bash

# Use newly built oqsprovider to generate CMS signed files for alg $1
# Assumed oqsprovider-certgen.sh to have run before for same algorithm

# uncomment to see what's happening:
# set -x

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

# Assumes certgen has been run before: Quick check for CMS file:

if [ -f tmp/signedfile.cms ]; then
    $OPENSSL_APP cms -verify -CAfile tmp/$1_CA.crt -inform pem -in tmp/signedfile.cms -crlfeol -out tmp/signeddatafile -provider oqsprovider -provider default
    diff tmp/signeddatafile tmp/inputfile
else
   echo "File tmp/signedfile.cms not found. Did CMS sign run before? Exiting."
   exit -1
fi

