[![oqs-provider](https://circleci.com/gh/open-quantum-safe/oqs-provider.svg?style=svg)](https://app.circleci.com/pipelines/github/open-quantum-safe/oqs-provider)

oqsprovider - Open Quantum Safe provider for OpenSSL (3.x)
==========================================================

Purpose
-------

This repository contains code to enable quantum-safe cryptography (QSC)
in a standard OpenSSL (3.x) distribution by way of implementing a single
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
signatures including CMS and CMP functionality are available via the OpenSSL
EVP interface. Key persistence is provided via the encode/decode
mechanism and X.509 data structures. Also available is support for 
TLS1.3 signature functionality via the [OpenSSL3 fetchable signature
algorithm feature](https://github.com/openssl/openssl/pull/19312).

Algorithms
----------

This implementation makes available the following quantum safe algorithms:

<!--- OQS_TEMPLATE_FRAGMENT_ALGS_START -->
- **BIKE**: `bikel1`, `p256_bikel1`, `x25519_bikel1`, `bikel3`, `p384_bikel3`, `x448_bikel3`, `bikel5`, `p521_bikel5`
- **CRYSTALS-Kyber**: `kyber512`, `p256_kyber512`, `x25519_kyber512`, `kyber768`, `p384_kyber768`, `x448_kyber768`, `x25519_kyber768`, `p256_kyber768`, `kyber1024`, `p521_kyber1024`
- **FrodoKEM**: `frodo640aes`, `p256_frodo640aes`, `x25519_frodo640aes`, `frodo640shake`, `p256_frodo640shake`, `x25519_frodo640shake`, `frodo976aes`, `p384_frodo976aes`, `x448_frodo976aes`, `frodo976shake`, `p384_frodo976shake`, `x448_frodo976shake`, `frodo1344aes`, `p521_frodo1344aes`, `frodo1344shake`, `p521_frodo1344shake`
- **HQC**: `hqc128`, `p256_hqc128`, `x25519_hqc128`, `hqc192`, `p384_hqc192`, `x448_hqc192`, `hqc256`, `p521_hqc256`†
- **CRYSTALS-Dilithium**:`dilithium2`\*, `p256_dilithium2`\*, `rsa3072_dilithium2`\*, `dilithium3`\*, `p384_dilithium3`\*, `dilithium5`\*, `p521_dilithium5`\*
- **Falcon**:`falcon512`\*, `p256_falcon512`\*, `rsa3072_falcon512`\*, `falcon1024`\*, `p521_falcon1024`\*

- **SPHINCS-SHA2**:`sphincssha2128fsimple`\*, `p256_sphincssha2128fsimple`\*, `rsa3072_sphincssha2128fsimple`\*, `sphincssha2128ssimple`\*, `p256_sphincssha2128ssimple`\*, `rsa3072_sphincssha2128ssimple`\*, `sphincssha2192fsimple`\*, `p384_sphincssha2192fsimple`\*, `sphincssha2192ssimple`, `p384_sphincssha2192ssimple`, `sphincssha2256fsimple`, `p521_sphincssha2256fsimple`, `sphincssha2256ssimple`, `p521_sphincssha2256ssimple`
- **SPHINCS-SHAKE**:`sphincsshake128fsimple`\*, `p256_sphincsshake128fsimple`\*, `rsa3072_sphincsshake128fsimple`\*, `sphincsshake128ssimple`, `p256_sphincsshake128ssimple`, `rsa3072_sphincsshake128ssimple`, `sphincsshake192fsimple`, `p384_sphincsshake192fsimple`, `sphincsshake192ssimple`, `p384_sphincsshake192ssimple`, `sphincsshake256fsimple`, `p521_sphincsshake256fsimple`, `sphincsshake256ssimple`, `p521_sphincsshake256ssimple`

<!--- OQS_TEMPLATE_FRAGMENT_ALGS_END -->

As the underlying [liboqs](https://github.com/open-quantum-safe/liboqs)
at build time may be configured to not enable all algorithms, it is
advisable to check the possible subset of algorithms actually enabled
via the standard commands, i.e.,
`openssl list -signature-algorithms -provider oqsprovider` and
`openssl list -kem-algorithms -provider oqsprovider`.

In addition, algorithms not denoted with "\*" above are not enabled for
TLS operations. This designation can be changed by modifying the
"enabled" flags in the main [algorithm configuration file](oqs-template/generate.yml)
and re-running the generator script `python3 oqs-template/generate.py`.

It is possible to select only algorithms of a specific bit strength by using
the openssl property selection mechanism on the key "oqsprovider.security_bits",
e.g., as such: `openssl list -kem-algorithms -propquery oqsprovider.security_bits=256`.
The bit strength of hybrid algorithms is always defined by the bit strength
of the classic algorithm.

In order to enable parallel use of classic and quantum-safe cryptography 
this provider also provides different hybrid algorithms, combining classic
and quantum-safe methods: These are listed above with a prefix denoting a
classic algorithm, e.g., for elliptic curve: "p256_".

A full list of algorithms, their interoperability code points and OIDs as well
as a method to dynamically adapt them are documented in [ALGORITHMS.md](ALGORITHMS.md).

*Note:* `oqsprovider` depends for TLS session setup and hybrid operations
on OpenSSL providers for classic crypto operations. Therefore it is essential
that a provider such as `default` or `fips` is configured to be active. See
`tests/oqs.cnf` or `scripts/openssl-ca.cnf` for examples.

Building and testing -- Quick start
-----------------------------------

All component builds and testing described in detail below can be executed by
running the scripts `scripts/fullbuild.sh` and `scripts/runtests.sh`
respectively (tested on Linux Ubuntu and Mint as well as OSX).

By default, these scripts always build and test against the current OpenSSL `master` branch.

These scripts can be configured by setting various environment variables as documented in the scripts.
For information the following environment settings may be of most interest:

- OPENSSL_INSTALL: Directory of an existing, non-standard OpenSSL binary distribution
- OPENSSL_BRANCH: Tag of a specific OpenSSL release to be built and used in testing


Building and testing
--------------------

## Pre-requisites

To be able to build `oqsprovider`, OpenSSL 3.0 and liboqs need to be installed.
It's not important where they are installed, just that they are.

For building, minimum requirements are a C compiler, git access and `cmake`.
For Linux these commands can typically be installed by running for example

    sudo apt install build-essential git cmake

### OpenSSL 3

If OpenSSL3 is not already installed, the following shows an example for building
and installing the latest/`master` branch of OpenSSL 3 in `.local`:

    git clone git://git.openssl.org/openssl.git
    cd openssl
    ./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw
    cd ..

For [OpenSSL implementation limitations, e.g., regarding provider feature usage and support,
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

`oqsprovider` using the local OpenSSL3 build as done above can be built for example via the following:

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

## Packaging

A build target to create .deb packaging is available via the standard `package`
target, e.g., executing `make package` in the `_build` subdirectory.

## Build and test options

### Size optimizations

In order to reduce the size of the oqsprovider, it is possible to limit the number
of algorithms supported, e.g., to the set of NIST standardized algorithms. This is
facilitated by setting the `liboqs` build option `-DOQS_ALGS_ENABLED=STD`.

### ninja

By adding the standard CMake option `-GNinja` the ninja build system can be used,
enabling the usual `ninja`, `ninja test`, or `ninja package` commands.

### NDEBUG

By adding the standard CMake option `-DCMAKE_BUILD_TYPE=Release` to the
`oqsprovider` build command, debugging output is disabled.

### OQS_SKIP_TESTS

By setting this environment variable, testing of specific
algorithm families as listed [here](https://github.com/open-quantum-safe/openssl#supported-algorithms)
can be disabled in testing. For example

    OQS_SKIP_TESTS="sphincs" ./scripts/runtests.sh

excludes all algorithms of the "Sphincs" family.

*Note*: By default, interoperability testing with oqs-openssl111 is no longer
performed by default but can be manually enabled in the script `scripts/runtests.sh`.

### Key Encoding

By setting `-DUSE_ENCODING_LIB=<ON/OFF>` at compile-time, oqs-provider can be compiled with with an an external encoding library `qsc-key-encoder`. Configuring the encodings is done via environment as described in [ALGORITHMS.md](ALGORITHMS.md).

By setting `-DNOPUBKEY_IN_PRIVKEY=<ON/OFF>` at compile-time, it can be further specified to omit explicitly serializing the public key in a `privateKey` structure. The default value is `OFF`.

Building on Windows
--------------------
The following steps have been tested on Windows 10 and 11 using MSYS2 MINGW64 and were successful. However, building with Visual Studio 2019 was unsuccessful (see [#47](https://github.com/open-quantum-safe/oqs-provider/issues/47)). Note that the process of building on Windows is considered experimental and may need further adjustments. Please report further issues to [#47](https://github.com/open-quantum-safe/oqs-provider/issues/47). Despite skipping the testing process, setting up a test server and client with post-quantum cryptography algorithms can still be accomplished.

Using
-----

In order to exercise the `oqsprovider`, it needs to be explicitly activated.
One way to do this is to enable it in the OpenSSL config file. Detailed
explanations can be found for example
[here](https://wiki.openssl.org/index.php/OpenSSL_3.0#Providers).

Another alternative is to explicitly request its use on the command line.
The following examples use that option. All examples below assume openssl (3.0)
to be located in a folder `.local` in the local directory as per the
building examples above. Having OpenSSL(3) installed in a standard location
eliminates the need for specific PATH setting as showcased below.

## Checking provider version information

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl list -providers -verbose -provider-path _build/lib -provider oqsprovider 

## Creating (classic) keys and certificates

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey rsa -keyout rsa_CA.key -out rsa_CA.crt -nodes -subj "/CN=test CA" -days 365 -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl genpkey -algorithm rsa -out rsa_srv.key
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -new -newkey rsa -keyout rsa_srv.key -out rsa_srv.csr -nodes -subj "/CN=test server" -config openssl/apps/openssl.cnf
    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -req -in rsa_srv.csr -out rsa_srv.crt -CA rsa_CA.crt -CAkey rsa_CA.key -CAcreateserial -days 365

## Setting up a (quantum-safe) test server

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake -provider-path _build/lib  -provider default -provider oqsprovider

## Running a client to interact with (quantum-safe) KEM algorithms

This can be facilitated for example by running

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl s_client -groups frodo640shake -provider-path _build/lib  -provider default -provider oqsprovider

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

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl req -x509 -new -newkey dilithium3 -keyout qsc.key -out qsc.crt -nodes -subj "/CN=oqstest" -days 365 -config openssl/apps/openssl.cnf -provider-path _build/lib -provider oqsprovider -provider default

By changing the `-newkey` parameter algorithm name [any of the 
supported quantum-safe or hybrid algorithms](https://github.com/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable#authentication)
can be utilized instead of the sample algorithm `dilithium3`.

Step 2: Sign data:

As
[the CMS standard](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
requires the presence of a digest algorithm, while quantum-safe crypto
does not, in difference to the QSC certificate creation command above,
passing a message digest algorithm via the `-md` parameter is mandatory.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -in inputfile -sign -signer qsc.crt -inkey qsc.key -nodetach -outform pem -binary -out signedfile -md sha512 -provider-path _build/lib  -provider default -provider oqsprovider

Data to be signed is to be contained in the file named `inputfile`. The
resultant CMS output is contained in file `signedfile`. The QSC algorithm
used is the same signature algorithm utilized for signing the certificate
`qsc.crt`.

#### Verifying data

Continuing the example above, the following command verifies the CMS file
`signedfile` and outputs the `outputfile`. Its contents should be identical
to the original data in `inputfile` above.

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl cms -verify -CAfile qsc.crt -inform pem -in signedfile -crlfeol -out outputfile -provider-path _build/lib -provider oqsprovider -provider default

Note that it is also possible to build proper QSC certificate chains
using the standard OpenSSL calls. For sample code see
[scripts/oqsprovider-certgen.sh](scripts/oqsprovider-certgen.sh).

### Support of `dgst` (and sign)

Also tested to operate OK is the [openssl dgst](https://www.openssl.org/docs/man3.0/man1/openssl-dgst.html)
command. Sample invocations building on the keys and certificate files in the examples above:

#### Signing

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/lib -provider oqsprovider -provider default -sign qsc.key -out dgstsignfile inputfile

#### Verifying

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl dgst -provider-path _build/lib -provider oqsprovider -provider default -signature dgstsignfile -verify qsc.pubkey inputfile

The public key can be extracted from the certificate using standard openssl command:

    LD_LIBRARY_PATH=.local/lib64 .local/bin/openssl x509 -provider-path _build/lib -provider oqsprovider -provider default -in qsc.crt -pubkey -noout > qsc.pubkey

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

Note on OpenSSL versions
------------------------

`oqsprovider` is written to ensure building on all versions of OpenSSL
supporting the provider concept. However, OpenSSL still is in active
development regarding features supported via the provider interface.
Therefore some functionalities documented above are only supported
with specific OpenSSL versions:

## 3.0/3.1

In these versions, CMS functionality implemented in providers is not
supported: The resolution of https://github.com/openssl/openssl/issues/17717
has not been not getting back-ported to OpenSSL3.0.

Also not supported in this version are provider-based signature algorithms
used during TLS1.3 operations as documented in https://github.com/openssl/openssl/issues/10512.

## 3.2(-dev)

After https://github.com/openssl/openssl/pull/19312 landed, (also PQ) signature
algorithms are working in TLS1.3 (handshaking); after https://github.com/openssl/openssl/pull/20486
has landed, also algorithms with very long signatures are supported.

liboqs dependency
-----------------

As `oqsprovider` is dependent on `liboqs` for the implementation of the PQ algorithms
there is a mechanism to adapt the functionality of a specific `liboqs` version to the
current `oqsprovider` version: The use of the code generator script `oqs-template/generate.py`
which in turn is driven by any of the `liboqs` release-specific `oqs-template/generate.yml[-release]`
files. The same file(s) also define the (default) TLS IDs of all algorithms included and
therefore represent the interoperability level at a specific point in time (of development
of `oqsprovider` and `liboqs`).

By default, `oqsprovider` always uses the most current version of `liboqs` code, but by
setting the environment variable "LIBOQS_BRANCH" when running the `scripts/fullbuild.sh`
script, code will be generated to utilize a specific, supported `liboqs` release. The
script `scripts/revertmain.sh` can be used to revert all code back to the default,
`main`-branch tracking strategy. This can be used, for example, to facilitate a release
of `oqsprovider` to track an old `liboqs` release.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to the `oqsprovider` include:

- Michael Baentsch
- Christian Paquin
- Richard Levitte
- Basil Hess
- Julian Segeth
- Alex Zaslavsky

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
