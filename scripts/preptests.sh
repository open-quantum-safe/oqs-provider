#!/bin/bash

# Assumption: openssl is checked out in folder openssl and tests reside in test
OPENSSL_SRC=openssl

# first, get orig test code:
cp $OPENSSL_SRC/test/helpers/ssltestlib.c test
cp $OPENSSL_SRC/test/helpers/ssltestlib.h test
mkdir -p test/oqs_test_groups 
cp -R $OPENSSL_SRC/test/certs/ test/oqs_test_groups/certs
cp $OPENSSL_SRC/test/recipes/90-test_sslapi_data/passwd.txt test/oqs_test_groups/passwd.txt

# finally, apply patches; fail if patch fails:
patch test/ssltestlib.c test/ssltestlib.c.patch
if [ $? -ne 0 ]; then
   exit -1
fi
patch test/ssltestlib.h test/ssltestlib.h.patch
if [ $? -ne 0 ]; then
   exit -1
fi
