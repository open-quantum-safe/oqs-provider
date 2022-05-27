[![oqs-provider](https://circleci.com/gh/open-quantum-safe/oqs-provider.svg?style=svg)](https://app.circleci.com/pipelines/github/open-quantum-safe/oqs-provider)

oqsprovider - Open Quantum Safe provider for OpenSSL (3.0)
==========================================================

Purpose
-------

This repository contains code to enable quantum-safe cryptography (QSC)
in a standard OpenSSL (3.0) distribution by way of implementing a single
shared library, the OQS
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html).

This repository has been derived from the [OQS-OpenSSL3 branch in
https://github.com/open-quantum-safe/openssl](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL3)
creating a provider that can be built outside the OpenSSL source tree.

Status
------

Currently this provider fully enables quantum-safe cryptography for KEM
key establishment in TLS1.3 including management of such keys via the
OpenSSL (3.0) provider interface and hybrid KEM schemes. Also, QSC
signatures including CMS functionality are available via the OpenSSL
EVP interface. Key persistence is provided via the encode/decode
mechanism and X.509 data structures.

For information about the available QSC algorithms,
[refer to the OQS-OpenSSL documentation](https://github.com/open-quantum-safe/openssl#supported-algorithms).

In addition to the hybrid key exchange algorithms listed in the [OQS-OpenSSL documentation](https://github.com/open-quantum-safe/openssl#supported-algorithms), oqs-provider supports some more hybrid algorithms. If ``<KEX>`` is any of the key exchange algorithms listed in the [OQS-OpenSSL documentation](https://github.com/open-quantum-safe/openssl#supported-algorithms), the following hybrid algorithms are supported:

- if `<KEX>` claims NIST L1 or L2 security, oqs-provider provides the method `x25519_<KEX>`, which combines `<KEX>` with X25519.
- if `<KEX>` claims NIST L3 or L4 security, oqs-provider provides the method `x448_<KEX>`, which combines `<KEX>` with X448.

For example, since `kyber768` [claims NIST L3 security](https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/kem/kyber.md), the hybrid `x448_kyber768` is available.

Open work items are
- (CI) Testing on platforms other than Ubuntu (x86_64)
- fully TLS-integrated quantum-safe signature functionality

If any of these features are needed, please refer to and use the
[OQS-OpenSSL1.1.1](https://github.com/open-quantum-safe/openssl) fork
where they are already implemented.

*Note:* `oqsprovider` depends for TLS session setup and hybrid operations
on OpenSSL providers for classic crypto operations. Therefore it is essential
that a provider such as `default` or `fips` is configured to be active. See
`tests/oqs.cnf` for an example.

Building and testing -- Quick start
-----------------------------------

All component builds and testing described in detail below can be executed by
running the scripts `scripts/fullbuild.sh` and `scripts/runtests.sh`
respectively (tested on Linux Ubuntu and Mint).


Building and testing
--------------------

## Pre-requisites

To be able to build `oqsprovider`, OpenSSL 3.0 and liboqs need to be installed.
It's not important where they are installed, just that they are.

For building, minimum requirements are a C compiler, git access and `cmake`.
For Linux these commands can typically be installed by running for example

    sudo apt install build-essential git cmake

### OpenSSL (3.0)

Example for building and installing OpenSSL 3.0 in `.local`:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw
    cd ..

For [OpenSSL implementation limitations, e.g., regarding provider feature usage and support,
see here](https://wiki.openssl.org/index.php/OpenSSL_3.0#STATUS_of_current_development).

*Note*: Building has last been validated with OpenSSL version/tag `openssl-3.0.0`
even though the goal of this project is to always build and work with the latest
OpenSSL `master` branch code.

### liboqs

Example for building and installing liboqs in `.local`:

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../.local -S . -B _build
    cmake --build _build && cmake --install _build
    cd ..

Further `liboqs` build options are [documented here](https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs).

## Building the provider

`oqsprovider` can be built for example via the following:

    cmake -DOPENSSL_ROOT_DIR=$(pwd)/.local -DCMAKE_PREFIX_PATH=$(pwd)/.local -S . -B _build
    cmake --build _build

## Testing

Core component testing can be run via the following command:

    (cd _build; ctest)

Add `-V` to the `ctest` command for verbose output.

*Note*: Some parts of testing depend on OpenSSL components. Be sure to have
these available (done automatically by the scripts provided).
See [the test README](test/README.md) for details.

Additional interoperability tests (with OQS-OpenSSL1.1.1) are available in the
script `scripts/runtests.sh`.

## Build and test options

### NDEBUG

By adding the standard CMake option `-DCMAKE_BUILD_TYPE=Release` to the
`oqsprovider` build command, debugging output is disabled.

### OQS_SKIP_TESTS

By setting this environment variable, OpenSSL 1.1.1 interoperability testing
and algorithm families as listed [here](https://github.com/open-quantum-safe/openssl#supported-algorithms)
can be disabled in testing. For example

    OQS_SKIP_TESTS="111,rainbow" ./scripts/runtests.sh

excludes OpenSSL1.1.1 interop testing as well as all algorithms of the
"Rainbow" family.

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

## Checking provider version information

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl list -providers -verbose -provider-path _build/oqsprov -provider oqsprovider 

## Creating (classic) keys and certificates

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey rsa -keyout rsa_CA.key -out rsa_CA.crt -nodes -subj "/CN=test CA" -days 365 -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl genpkey -algorithm rsa -out rsa_srv.key
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -new -newkey rsa -keyout rsa_srv.key -out rsa_srv.csr -nodes -subj "/CN=test server" -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -req -in rsa_srv.csr -out rsa_srv.crt -CA rsa_CA.crt -CAkey rsa_CA.key -CAcreateserial -days 365

## Setting up a (quantum-safe) test server

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake -provider-path _build/oqsprov  -provider default -provider oqsprovider

## Running a client to interact with (quantum-safe) KEM algorithms

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_client -groups frodo640shake -provider-path _build/oqsprov  -provider default -provider oqsprovider

By issuing the command `GET /` the quantum-safe crypto enabled OpenSSL3
server returns details about the established connection.

Any [available KEM algorithm](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable#key-exchange) can be selected by passing it in the `-groups` option.

## S/MIME message signing -- Cryptographic Message Syntax (CMS)

Also possible is the creation and verification of quantum-safe digital
signatures using [CMS](https://datatracker.ietf.org/doc/html/rfc5652).

#### Signing data

For creating signed data, two steps are required: One is the creation
of a certificate using a QSC algorithm; the second is the use of this
certificate (and its signature algorithm) to create the signed data:

Step 1: Create quantum-safe key pair and self-signed certificate:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey dilithium3 -keyout qsc.key -out qsc.crt -nodes -subj "/CN=oqstest" -days 365 -config openssl/apps/openssl.cnf -provider-path _build/oqsprov -provider oqsprovider -provider default

By changing the `-newkey` parameter algorithm name [any of the 
supported quantum-safe or hybrid algorithms](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable#authentication)
can be utilized instead of the sample algorithm `dilithium3`.

Step 2: Sign data:

As
[the CMS standard](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
requires the presence of a digest algorithm, while quantum-safe crypto
does not, in difference to the QSC certificate creation command above,
passing a message digest algorithm via the `-md` parameter is mandatory.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -in inputfile -sign -signer qsc.crt -inkey qsc.key -nodetach -outform pem -binary -out signedfile -md sha512 -provider-path _build/oqsprov  -provider default -provider oqsprovider

Data to be signed is to be contained in the file named `inputfile`. The
resultant CMS output is contained in file `signedfile`. The QSC algorithm
used is the same signature algorithm utilized for signing the certificate
`qsc.crt`.

#### Verifying data

Continuing the example above, the following command verifies the CMS file
`signedfile` and outputs the `outputfile`. Its contents should be identical
to the original data in `inputfile` above.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -verify -CAfile qsc.crt -inform pem -in signedfile -crlfeol -out outputfile -provider-path _build/oqsprov -provider oqsprovider -provider default

Note that it is also possible to build proper QSC certificate chains
using the standard OpenSSL calls. For sample code see
[scripts/oqsprovider-certgen.sh](scripts/oqsprovider-certgen.sh).

### Support of `dgst` (and sign)

Also tested to operate OK is the [openssl dgst](https://www.openssl.org/docs/man3.0/man1/openssl-dgst.html)
command. Sample invocations building on the keys and certificate files in the examples above:

#### Signing

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/oqsprov -provider oqsprovider -provider default -sign qsc.key -out dgstsignfile inputfile

#### Verifying

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/oqsprov -provider oqsprovider -provider default -signature dgstsignfile -verify qsc.pubkey inputfile

The public key can be extracted from the certificate using standard openssl command:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -provider-path _build/oqsprov -provider oqsprovider -provider default -in qsc.crt -pubkey -noout > qsc.pubkey

The `dgst` command is not tested for interoperability with [oqs-openssl111](https://github.com/open-quantum-safe/openssl).

### Note on randomness provider

`oqsprovider` does not implement its own
[DRBG](https://csrc.nist.gov/glossary/term/Deterministic_Random_Bit_Generator).
Therefore by default it relies on OpenSSL to provide one. Thus,
either the default or fips provider must be loaded for QSC algorithms
to have access to OpenSSL-provided randomness. Check out
[OpenSSL provider documentation](https://www.openssl.org/docs/manmaster/man7/provider.html)
and/or [OpenSSL command line options](https://www.openssl.org/docs/manmaster/man1/openssl.html)
on how to facilitate this. Or simply use the sample command
lines documented in this README.

This dependency could be eliminated by building `liboqs` without
OpenSSL support ([OQS_USE_OPENSSL=OFF](https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs#OQS_USE_OPENSSL)),
which of course would be an unusual approach for an OpenSSL-OQS provider.

### Note on KEM Decapsulation API

The OpenSSL [`EVP_PKEY_decapsulate` API](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decapsulate.html) specifies an explicit return value for failure. For security reasons, most KEM algorithms available from liboqs do not return an error code if decapsulation failed. Successful decapsulation can instead be implicitly verified by comparing the original and the decapsulated message.

Team
----
The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to the `oqsprovider` include:

- Michael Baentsch
- Christian Paquin
- Richard Levitte
- Basil Hess

Acknowledgments
---------------

The `oqsprovider` project is supported through the [NGI Assure Fund](https://nlnet.nl/assure),
a fund established by [NLnet](https://nlnet.nl) with financial
support from the European Commission's [Next Generation Internet programme](https://www.ngi.eu),
under the aegis of DG Communications Networks, Content and Technology
under grant agreement No 957073.

Financial support for the development of Open Quantum Safe has been provided
by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have
dedicated programmer time to contribute source code to OQS, including
Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been
supported by various research grants, including funding from the Natural
Sciences and Engineering Research Council of Canada (NSERC); see
[here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and
[here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf)
for funding acknowledgments.
