#!/bin/bash

# Use newly built oqsprovider to generate CMS signed files for alg $1
# Also used to test X509 pubkey extract and sign/verify using openssl dgst
# Assumes .local to contain openssl(3) and oqsprovider to be in _build folder
# Assumed oqsprovider-certgen.sh to have run before for same algorithm

# uncomment to see what's happening:
# set -x

if [ $# -ne 1 ]; then
    echo "Usage: $0 <algorithmname>. Exiting."
    exit 1
fi

# Assumes certgen has been run before: Quick check

if [ -f tmp/$1_CA.crt ]; then
   echo "Sometext to sign" > tmp/inputfile
else
   echo "File tmp/$1_CA.crt not found. Did certgen run before? Exiting."
   exit -1
fi

export OPENSSL_MODULES=_build/oqsprov
export LD_LIBRARY_PATH=.local/lib64
.local/bin/openssl x509 -provider oqsprovider -provider default -in tmp/$1_srv.crt -pubkey -noout > tmp/$1_srv.pubkey && .local/bin/openssl cms -in tmp/inputfile -sign -signer tmp/$1_srv.crt -inkey tmp/$1_srv.key -nodetach -outform pem -binary -out tmp/signedfile.cms -md sha512 -provider oqsprovider -provider default && .local/bin/openssl dgst -provider oqsprovider -provider default -sign tmp/$1_srv.key -out tmp/dgstsignfile tmp/inputfile

if [ $? -eq 0 ]; then
# run internal test:
   .local/bin/openssl cms -verify -CAfile tmp/$1_CA.crt -inform pem -in tmp/signedfile.cms -crlfeol -out tmp/signeddatafile -provider oqsprovider -provider default && diff tmp/signeddatafile tmp/inputfile && .local/bin/openssl dgst -provider oqsprovider -provider default -signature tmp/dgstsignfile -verify tmp/$1_srv.pubkey tmp/inputfile
else
   exit -1
fi
