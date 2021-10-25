#!/bin/bash

if [ $# -gt 0 ]; then
   rm -rf _build
fi

if [ ! -d "openssl" ]; then
   echo "openssl doesn't reside where expected: Cloning and building..."
   # for full debug build add: enable-trace enable-fips --debug
   git clone git://git.openssl.org/openssl.git && cd openssl && ./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw && cd ..
   if [ $? -ne 0 ]; then
     echo "openssl build failed. Exiting."
     exit -1
   fi
fi

# Check whether liboqs is built:
if [ ! -f ".local/lib/liboqs.a" ]; then
   echo "liboqs static lib not built: Cloning and building..."
   # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
   git clone https://github.com/open-quantum-safe/liboqs.git && cd liboqs && cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build && cmake --build _build && cmake --install _build && cd ..
   if [ $? -ne 0 ]; then
     echo "liboqs build failed. Exiting."
     exit -1
   fi
fi

# Check whether provider is built:
if [ ! -f "_build/oqsprov/oqsprovider.so" ]; then
   echo "oqsprovider not built: Building..."
   # for full debug build add: -DCMAKE_BUILD_TYPE=Debug
   cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local -DCMAKE_PREFIX_PATH=$(pwd)/.local -S . -B _build && cmake --build _build
   if [ $? -ne 0 ]; then
     echo "provider build failed. Exiting."
     exit -1
   fi
fi

./scripts/runtests.sh $@


