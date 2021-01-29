oqsprovider - Open Quantum Safe provider for OpenSSL 3.0
========================================================

This is derived from the OQS-OpenSSL3 branch in
https://github.com/open-quantum-safe/openssl to
make an independent and external provider.

Pre-requisits
-------------

To be able to build oqsprovider, you must build and install OpenSSL 3.0 (not
yet release) and liboqs.  It's not important where they are installed, just
that they are.

Example for building and installing OpenSSL 3.0 in `$HOME/.local` (only
development files are installed):

    git clone git://git.openssl.org/openssl.git openssl
    cd openssl
    ./config --prefix=$(echo $HOME/.local) && make && make install_dev
    cd ..

Example for building and installing liboqs in `$HOME/.local`:

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local -S . -B _build
    cmake --build _build
    cmake --install _build
    cd ..

Quick building and testing instructions
---------------------------------------

To build oqsprovider, do the following

    cmake -DOPENSSL_ROOT_DIR=$HOME/.local -DCMAKE_PREFIX_PATH=$HOME/.local \
        -S . -B _build
    cmake --build _build

To test oqsprovider, do the following:

    (cd _build; ctest)

To test oqsprovider verbosely, do the following:

    (cd _build; ctest -V)
