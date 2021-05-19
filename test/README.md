# oqs-provider testing

The tests in this folder are running separately from the OpenSSL test framework but utilize some of its plumbing.

## Patches

Not the full OpenSSL test infrastructure is embedded such as to allow the tests to run stand-alone. Therefore, some modifications are made to test support code via patches.

The required patches are generated within this folder and assuming OpenSSL has been cloned into `../openssl` as per the [README](../README.md) using this command

   diff -u ../openssl/test/helpers/ssltestlib.c ssltestlib.c > ssltestlib.c.patch

As OpenSSL continues to evolve it may be necessary to update these patches.

## Applying patches

Patches are applied by running `scripts/preptests.sh` in the oqs-provider main folder (`..`) before building oqs-provider.
