#!/bin/bash

# Use newly built oqsprovider to generate CMS signed files for alg $1
# Also used to test X509 pubkey extract and sign/verify using openssl dgst
# Assumed oqsprovider-certgen.sh to have run before for same algorithm

# uncomment to see what's happening:
#set -x

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

# Assumes certgen has been run before: Quick check

if [ -f tmp/$1_CA.crt ]; then
   echo "Sometext to sign" > tmp/inputfile
else
   echo "File tmp/$1_CA.crt not found. Did certgen run before? Exiting."
   exit -1
fi

$OPENSSL_APP x509 -provider oqsprovider -provider default -in tmp/$1_srv.crt -pubkey -noout > tmp/$1_srv.pubkey && $OPENSSL_APP cms -in tmp/inputfile -sign -signer tmp/$1_srv.crt -inkey tmp/$1_srv.key -nodetach -outform pem -binary -out tmp/signedfile.cms -md sha512 -provider oqsprovider -provider default && $OPENSSL_APP dgst -provider oqsprovider -provider default -sign tmp/$1_srv.key -out tmp/dgstsignfile tmp/inputfile

if [ $? -eq 0 ]; then
# run internal test:
   $OPENSSL_APP cms -verify -CAfile tmp/$1_CA.crt -inform pem -in tmp/signedfile.cms -crlfeol -out tmp/signeddatafile -provider oqsprovider -provider default && diff tmp/signeddatafile tmp/inputfile && $OPENSSL_APP dgst -provider oqsprovider -provider default -signature tmp/dgstsignfile -verify tmp/$1_srv.pubkey tmp/inputfile
else
   exit -1
fi
