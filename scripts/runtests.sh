#!/bin/sh

provider2openssl() {
    echo
    echo "Testing oqsprovider->oqs-openssl interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmssign.sh $1 sha3-384 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-cmsverify.sh $1
}

openssl2provider() {
    echo
    echo "Testing oqs-openssl->oqsprovider interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqs-openssl-cmssign.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmsverify.sh $1
}

localalgtest() {
    $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certgen.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-certverify.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/scripts/oqsprovider-cmssign.sh $1 >> interop.log 2>&1
    if [ $? -ne 0 ]; then
        echo "localalgtest $1 failed. Exiting.".
        exit 1
    fi
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

    # Check whether algorithm is supported at all:
    $OPENSSL_APP list -signature-algorithms -provider oqsprovider | grep $1 > /dev/null 2>&1
    if [ $? -ne 1 ]; then
	if [ -z "$LOCALTESTONLY" ]; then
            provider2openssl $1 >> interop.log 2>&1 && openssl2provider $1 >> interop.log 2>&1
	else
            localalgtest $1
        fi
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
    export OPENSSL_MODULES=_build/lib
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

# by default, do not run interop tests as per 
# https://github.com/open-quantum-safe/oqs-provider/issues/32
# comment the following line if they should be run; be sure to
# have alignment in algorithms supported in that case
export LOCALTESTONLY="Yes"

echo "OpenSSL app: $OPENSSL_APP"

echo "Version information:"
$OPENSSL_APP version
$OPENSSL_APP list -providers -verbose -provider-path _build/lib -provider oqsprovider

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
interop sphincsharaka128frobust
interop p256_sphincsharaka128frobust
interop rsa3072_sphincsharaka128frobust
interop sphincsharaka128fsimple
interop p256_sphincsharaka128fsimple
interop rsa3072_sphincsharaka128fsimple
interop sphincssha256128frobust
interop p256_sphincssha256128frobust
interop rsa3072_sphincssha256128frobust
interop sphincssha256128ssimple
interop p256_sphincssha256128ssimple
interop rsa3072_sphincssha256128ssimple
interop sphincsshake256128fsimple
interop p256_sphincsshake256128fsimple
interop rsa3072_sphincsshake256128fsimple
##### OQS_TEMPLATE_FRAGMENT_ALGS_END

# Run built-in tests:
(cd _build; ctest $@)

# cleanup: TBC:
# decide for testing strategy when integrating to OpenSSL test harness:
# Keep scripts generating certs (testing more code paths) or use API?
#rm -rf tmp
echo
echo "All oqsprovider tests passed."

