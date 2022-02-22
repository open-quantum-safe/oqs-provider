#!/bin/sh

provider2openssl() {
    echo "Testing oqsprovider->oqs-openssl interop for $1:"
    ./scripts/oqsprovider-certgen.sh $1 && ./scripts/oqs-openssl-certverify.sh $1
}

openssl2provider() {
    echo "Testing oqs-openssl->oqsprovider interop for $1:"
    ./scripts/oqs-openssl-certgen.sh $1 && ./scripts/oqsprovider-certverify.sh $1
}

interop() {
    # check if we can use docker or not:
    docker info 2>&1 | grep Server > /dev/null

    if [ $? -ne 0 ]; then
        echo "Running local test only due to absence of docker:"
        ./scripts/oqsprovider-certgen.sh $1 && ./scripts/oqsprovider-certverify.sh $1
    else
        provider2openssl $1 && openssl2provider $1
    fi

}

# Output version:
LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl list -providers -verbose -provider-path _build/oqsprov -provider oqsprovider

# Run built-in tests:
(cd _build; ctest $@)

# Run interop-tests:
##### OQS_TEMPLATE_FRAGMENT_ALGS_START
interop dilithium2
interop p256_dilithium2
interop rsa3072_dilithium2
interop dilithium3
interop p384_dilithium3
interop dilithium5
interop p521_dilithium5
interop dilithium2_aes
interop p256_dilithium2_aes
interop rsa3072_dilithium2_aes
interop dilithium3_aes
interop p384_dilithium3_aes
interop dilithium5_aes
interop p521_dilithium5_aes
interop falcon512
interop p256_falcon512
interop rsa3072_falcon512
interop falcon1024
interop p521_falcon1024
interop picnicl1full
interop p256_picnicl1full
interop rsa3072_picnicl1full
interop picnic3l1
interop p256_picnic3l1
interop rsa3072_picnic3l1
interop rainbowIclassic
interop p256_rainbowIclassic
interop rsa3072_rainbowIclassic
interop rainbowVclassic
interop p521_rainbowVclassic
interop sphincsharaka128frobust
interop p256_sphincsharaka128frobust
interop rsa3072_sphincsharaka128frobust
interop sphincssha256128frobust
interop p256_sphincssha256128frobust
interop rsa3072_sphincssha256128frobust
interop sphincsshake256128frobust
interop p256_sphincsshake256128frobust
interop rsa3072_sphincsshake256128frobust
##### OQS_TEMPLATE_FRAGMENT_ALGS_END

# cleanup
rm -rf tmp


