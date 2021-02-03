[![oqs-provider](https://circleci.com/gh/open-quantum-safe/oqs-provider.svg?style=svg)](https://app.circleci.com/pipelines/github/open-quantum-safe/oqs-provider)

oqsprovider - Open Quantum Safe provider for OpenSSL (3.0)
==========================================================

Purpose
-------

This repository contains code to enable quantum-safe cryptography in a
standard OpenSSL (3.0) distribution by way of implementing a single shared
library, the OQS
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html).

This code is derived from the OQS-OpenSSL3 branch in
https://github.com/open-quantum-safe/openssl creating
an independent and (OpenSSL-)external provider.

Status
------

Currently this provider fully enables quantum-safe cryptography for KEM
key establishment in TLS1.3 including management of such keys via the
OpenSSL (3.0) provider interface. Also, OQS signatures are available via
the OpenSSL EVP interface. For information about the available OQS algorithms,
[refer to the OQS-OpenSSL documentation](https://github.com/open-quantum-safe/openssl#supported-algorithms).

Open work items are
- (CI) Testing on platforms other than Ubuntu 18.04 (x86_64)
- fully TLS-integrated quantum-safe signatures
- hybrid quantum-safe cryptography

If any of these functionalities are needed, please refer to the
[OQS-OpenSSL1.1.1](https://github.com/open-quantum-safe/openssl) fork.

Building and testing
--------------------

## Pre-requisites

To be able to build `oqsprovider`, OpenSSL 3.0 (not yet released) and liboqs
need to be installed.  It's not important where they are installed, just
that they are.

For building, minimum requirements are a C compiler, git access and `cmake`.
For Linux these commands can typically be installed by running for example

    sudo apt install build-essential git cmake

### OpenSSL (3.0)

Example for building and installing OpenSSL 3.0 in `.local`:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw
    cd ..

OpenSSL (3.0) is not yet released in a production version. For [limitations
see here](https://wiki.openssl.org/index.php/OpenSSL_3.0#STATUS_of_current_development).

### liboqs

Example for building and installing liboqs in `.local`:

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build
    cmake --build _build && cmake --install _build
    cd ..

Further `liboqs` build options are [documented here](https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs).

## Building the provider

`oqsprovider` can be build for example via the following:

    cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local -DCMAKE_PREFIX_PATH=$(pwd)/.local -S . -B _build
    cmake --build _build

## Testing

Testing can be run via the following command:

    (cd _build; ctest)

Add `-V` to the `ctest` command for verbose output.

*Note*: Some parts of testing depend on OpenSSL components. These can be
activated by executing `./scripts/preptests.sh` before building the provider.

## Build options

### NDEBUG

By adding the standard CMake option `-DCMAKE_BUILD_TYPE=Release` to the
`oqsprovider` build command, debugging output is disabled.

Using
-----

In order to exercise the `oqsprovider`, it needs to be explicitly activated.
One way to do this is to enable it in the OpenSSL config file. Detailed
explanations can be found for example
[here](https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers).

Another alternative is to explicitly request its use on the command line.
The following examples use that option. All examples below assume openssl (3.0)
to be located in a folder `.local` in the local directory as per the
building examples above. Installing openssl(3.0) in a standard location
eliminates the need for specific PATH setting as showcased below.

## Creating (classic) keys and certificates

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib .local/bin/openssl req -x509 -new -newkey rsa -keyout rsa_CA.key -out rsa_CA.crt -nodes -subj "/CN=test CA" -days 365 -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib .local/bin/openssl genpkey -algorithm rsa -out rsa_srv.key
    LD_LIBRARY_PATH=.local/lib .local/bin/openssl req -new -newkey rsa -keyout rsa_srv.key -out rsa_srv.csr -nodes -subj "/CN=test server" -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib .local/bin/openssl x509 -req -in rsa_srv.csr -out rsa_srv.crt -CA rsa_CA.crt -CAkey rsa_CA.key -CAcreateserial -days 365

## Setting up a (quantum-safe) test server

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib .local/bin/openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake -provider-path _build/oqsprov  -provider default -provider oqsprovider

## Running a client to interact with (quantum-safe) KEM algorithms

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib .local/bin/openssl s_client -groups frodo640shake -provider-path _build/oqsprov  -provider default -provider oqsprovider

By issuing the command `GET /` the quantum-safe crypto enabled OpenSSL3
server returns details about the established connection.

Any [available KEM algorithm](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable#key-exchange) can be selected by passing it in the `-groups` option.

Team
----
The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to the `oqsprovider` include:

- Michael Baentsch
- Christian Paquin
- Richard Levitte

Acknowledgments
---------------

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
