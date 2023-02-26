#!/bin/bash

# The following variables influence the operation of this build script:
# Argument -f: Soft clean, ensuring re-build of oqs-provider binary
# Argument -F: Hard clean, ensuring checkout and build of all dependencies
# EnvVar MAKE_PARAMS: passed to invocations of make; sample value: "-j"
# EnvVar LIBOQS_BRANCH: Defines branch/release of liboqs; default value "main"
# EnvVar OPENSSL_BRANCH: Defines branch/release of openssl; default value "master"
# EnvVar OQS_ALGS_ENABLED: If set, defines OQS algs to be enabled, e.g., "STD"

if [ $# -gt 0 ]; then
   if [ "$1" == "-f" ]; then
      rm -rf _build
   fi
   if [ "$1" == "-F" ]; then
      rm -rf _build openssl liboqs .local
   fi
fi

if [ -z "$LIBOQS_BRANCH" ]; then
   export LIBOQS_BRANCH=main
fi

if [ -z "$OPENSSL_BRANCH" ]; then
   export OPENSSL_BRANCH=master
fi

if [ -z "$OQS_ALGS_ENABLED" ]; then
   export DOQS_ALGS_ENABLED=""
else
   export DOQS_ALGS_ENABLED="$OQS_ALGS_ENABLED"
fi

if [ ! -d "openssl" ]; then
   echo "openssl doesn't reside where expected: Cloning and building..."
   # for full debug build add: enable-trace enable-fips --debug
   git clone --depth 1 --branch $OPENSSL_BRANCH git://git.openssl.org/openssl.git && cd openssl && ./config --prefix=$(echo $(pwd)/../.local) && make $MAKE_PARAMS && make install_sw && cd ..
   if [ $? -ne 0 ]; then
     echo "openssl build failed. Exiting."
     exit -1
   fi
fi

# Check whether liboqs is built:
if [ ! -f ".local/lib/liboqs.a" ]; then
   echo "liboqs static lib not built: Cloning and building..."
   # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
   # to optimize for size add -DOQS_ALGS_ENABLED= suitably to one of these values:
   #    STD: only include NIST standardized algorithms
   #    NIST_R4: only include algorithms in round 4 of the NIST competition
   #    All: include all algorithms supported by liboqs (default)
   git clone --depth 1 --branch $LIBOQS_BRANCH https://github.com/open-quantum-safe/liboqs.git && cd liboqs && cmake -GNinja $DOQS_ALGS_ENABLED -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build && cd _build && ninja && ninja install && cd ../..
   if [ $? -ne 0 ]; then
     echo "liboqs build failed. Exiting."
     exit -1
   fi
fi

# Check whether provider is built:
if [ ! -f "_build/oqsprov/oqsprovider.so" ]; then
   echo "oqsprovider not built: Building..."
   # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
   # for omitting public key in private keys add -DNOPUBKEY_IN_PRIVKEY=ON
   cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local -DCMAKE_PREFIX_PATH=$(pwd)/.local -S . -B _build && cmake --build _build
   if [ $? -ne 0 ]; then
     echo "provider build failed. Exiting."
     exit -1
   fi
fi

