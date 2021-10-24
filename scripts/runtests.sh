#!/bin/bash

provider2openssl() {
    echo "Testing oqsprovider->oqs-openssl interop for $1:"
    ./scripts/oqsprovider-certgen.sh $1 && ./scripts/oqs-openssl-certverify.sh $1
}

openssl2provider() {
    echo "Testing oqs-openssl->oqsprovider interop for $1:"
    ./scripts/oqs-openssl-certgen.sh $1 && ./scripts/oqsprovider-certverify.sh $1
}

interop() {
    provider2openssl $1 && openssl2provider $1
}

# Run built-in tests:
(cd _build; ctest $@)

# Run interop-tests:
##### OQS_TEMPLATE_FRAGMENT_ALGS_START
interop dilithium2
interop dilithium3
interop dilithium5
interop dilithium2_aes
interop dilithium3_aes
interop dilithium5_aes
interop falcon512
interop falcon1024
interop picnicl1full
interop picnic3l1
interop rainbowIclassic
interop rainbowVclassic
interop sphincsharaka128frobust
interop sphincssha256128frobust
interop sphincsshake256128frobust
##### OQS_TEMPLATE_FRAGMENT_ALGS_END

# cleanup
rm -rf tmp


