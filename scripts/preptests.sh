#!/bin/bash

# Assumption: openssl is checked out in folder $OPENSSL_BLDTOP and tests reside in test

if [ -z "$OPENSSL_BLDTOP" ]; then
    OPENSSL_BLDTOP=openssl
fi

# first, get orig test code:
cp $OPENSSL_BLDTOP/test/helpers/ssltestlib.c test
cp $OPENSSL_BLDTOP/test/helpers/ssltestlib.h test
mkdir -p test/oqs_test_groups 
cp -R $OPENSSL_BLDTOP/test/certs/ test/oqs_test_groups/certs
cp $OPENSSL_BLDTOP/test/recipes/90-test_sslapi_data/passwd.txt test/oqs_test_groups/passwd.txt

# finally, apply patches; fail if patch fails:
patch test/ssltestlib.c test/ssltestlib.c.patch
if [ $? -ne 0 ]; then
   exit -1
fi
patch test/ssltestlib.h test/ssltestlib.h.patch
if [ $? -ne 0 ]; then
   exit -1
fi
