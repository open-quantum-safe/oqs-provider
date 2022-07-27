#!/bin/sh

provider2openssl() {
    echo
    echo "Testing oqsprovider->oqs-openssl interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmssign.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-cmsverify.sh $1
}

openssl2provider() {
    echo
    echo "Testing oqs-openssl->oqsprovider interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-cmssign.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmsverify.sh $1
}

interop() {
    echo -n "."
    # check if we want to run this algorithm:
    if [ ! -z "$OQS_SKIP_TESTS" ]; then
        GREPTEST=$(echo $OQS_SKIP_TESTS | sed "s/\,/\\\|/g")
        if echo $1 | grep -q "$GREPTEST"; then
            echo "Not testing $1" >> interop.log
            return
        fi
    fi


    if [ -z "$LOCALTESTONLY" ]; then
        provider2openssl $1 >> interop.log 2>&1 && openssl2provider $1 >> interop.log 2>&1
    else
        $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certgen.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certverify.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmssign.sh $1 >> interop.log 2>&1
    fi

    if [ $? -ne 0 ]; then
        echo "Test for $1 failed. Terminating testing."
        exit 1
    fi
}

if [ -z "$OQS_PROVIDER_TESTSCRIPTS" ]; then
    export OQS_PROVIDER_TESTSCRIPTS=.
fi

if [ -z "$OPENSSL_APP" ]; then
    export OPENSSL_APP=openssl/apps/openssl
fi

if [ -z "$OPENSSL_MODULES" ]; then
    export OPENSSL_MODULES=_build/oqsprov
fi

if [ -z "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH=.local/lib64
fi

if [ ! -z "$OQS_SKIP_TESTS" ]; then
   echo "Skipping algs $OQS_SKIP_TESTS"
fi

# check if we can use docker or not:
docker info 2>&1 | grep Server > /dev/null
if [ $? -ne 0 ]; then
   echo "No OQS-OpenSSL111 interop test because of absence of docker"
   export LOCALTESTONLY="Yes"
fi

# check if OpenSSL111 interop tests are disabled:
echo $OQS_SKIP_TESTS | grep -q "111"
if [ $? -eq 0 ]; then
   echo "No OQS-OpenSSL111 interop tests due to skip instruction in $OQS_SKIP_TESTS"
   export LOCALTESTONLY="Yes"
fi

echo "OpenSSL app: $OPENSSL_APP"

# Output version:
$OPENSSL_APP list -providers -verbose -provider-path _build/oqsprov -provider oqsprovider

# Run built-in tests:
(cd _build; ctest $@)

# Run interop-tests:
echo "Cert gen/verify, CMS sign/verify tests for all enabled algorithms commencing..."
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
echo
echo "All oqsprovider tests passed."

