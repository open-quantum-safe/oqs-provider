#!/bin/sh

rv=0

provider2openssl() {
    echo
    echo "Testing oqsprovider->oqs-openssl interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-cmssign.sh $1 sha3-384 && $OQS_PROVIDER_TESTSCRIPTS/oqs-openssl-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/oqs-openssl-cmsverify.sh $1
}

openssl2provider() {
    echo
    echo "Testing oqs-openssl->oqsprovider interop for $1:"
    $OQS_PROVIDER_TESTSCRIPTS/oqs-openssl-certgen.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/oqs-openssl-cmssign.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-certverify.sh $1 && $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-cmsverify.sh $1
}

localalgtest() {
    $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-certgen.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-certverify.sh $1 >> interop.log 2>&1 && $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-cmssign.sh $1 >> interop.log 2>&1 &&  $OQS_PROVIDER_TESTSCRIPTS/oqsprovider-ca.sh $1 >> interop.log 2>&1
    if [ $? -ne 0 ]; then
        echo "localalgtest $1 failed. Exiting.".
        cat interop.log
        exit 1
    fi
}

interop() {
    echo ".\c"
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
        cat interop.log
        exit 1
    fi
}

if [ -z "$OQS_PROVIDER_TESTSCRIPTS" ]; then
    export OQS_PROVIDER_TESTSCRIPTS=$(pwd)/scripts
fi

if [ ! -z "$OPENSSL_INSTALL" ]; then
    # trying to set config variables suitably for pre-existing OpenSSL installation
    if [ -f $OPENSSL_INSTALL/bin/openssl ]; then
        export OPENSSL_APP=$OPENSSL_INSTALL/bin/openssl
    fi
    if [ -d $OPENSSL_INSTALL/lib64 ]; then
        export LD_LIBRARY_PATH=$OPENSSL_INSTALL/lib64
    fi
    if [ -f $OPENSSL_INSTALL/ssl/openssl.cnf ]; then
        export OPENSSL_CONF=$OPENSSL_INSTALL/ssl/openssl.cnf
    fi
else
    if [ -z "$OPENSSL_CONF" ]; then
        export OPENSSL_CONF=$(pwd)/scripts/openssl-ca.cnf
    fi
fi

if [ -z "$OPENSSL_APP" ]; then
    if [ -f $(pwd)/openssl/apps/openssl ]; then
        export OPENSSL_APP=$(pwd)/openssl/apps/openssl
    else # if no local openssl src directory is found, rely on PATH...
        export OPENSSL_APP=openssl
    fi
fi

if [ -z "$OPENSSL_MODULES" ]; then
    export OPENSSL_MODULES=$(pwd)/_build/lib
fi

if [ -z "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH=$(pwd)/.local/lib64
fi

if [ ! -z "$OQS_SKIP_TESTS" ]; then
   echo "Skipping algs $OQS_SKIP_TESTS"
fi

echo "Test setup:"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "OPENSSL_APP=$OPENSSL_APP"
echo "OPENSSL_CONF=$OPENSSL_CONF"
echo "OPENSSL_MODULES=$OPENSSL_MODULES"

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

echo "Version information:"
$OPENSSL_APP version
$OPENSSL_APP list -providers -verbose -provider-path _build/lib -provider oqsprovider

# Run interop-tests:
echo "Cert gen/verify, CMS sign/verify, CA tests for all enabled algorithms commencing..."
##### OQS_TEMPLATE_FRAGMENT_ALGS_START
interop dilithium2
interop p256_dilithium2
interop rsa3072_dilithium2
interop dilithium3
interop p384_dilithium3
interop dilithium5
interop p521_dilithium5
interop falcon512
interop p256_falcon512
interop rsa3072_falcon512
interop falcon1024
interop p521_falcon1024
interop sphincssha256128fsimple
interop p256_sphincssha256128fsimple
interop rsa3072_sphincssha256128fsimple
interop sphincssha256128ssimple
interop p256_sphincssha256128ssimple
interop rsa3072_sphincssha256128ssimple
interop sphincssha256192fsimple
interop p384_sphincssha256192fsimple
interop sphincsshake256128fsimple
interop p256_sphincsshake256128fsimple
interop rsa3072_sphincsshake256128fsimple
##### OQS_TEMPLATE_FRAGMENT_ALGS_END

echo

# Run built-in tests:
# Without removing OPENSSL_CONF ctest hangs... ???
unset OPENSSL_CONF
cd _build && ctest $@ && cd ..

if [ $? -ne 0 ]; then
   rv=1
fi

# cleanup: TBC:
# decide for testing strategy when integrating to OpenSSL test harness:
# Keep scripts generating certs (testing more code paths) or use API?
#rm -rf tmp
echo

if [ $rv -ne 0 ]; then
   echo "Tests failed."
else
   echo "All oqsprovider tests passed."
fi
exit $rv

