[![GitHub actions](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/linux.yml/badge.svg)](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/linux.yml)
[![GitHub actions](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/windows.yml/badge.svg)](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/windows.yml)
[![GitHub actions](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/macos.yml/badge.svg)](https://github.com/open-quantum-safe/oqs-provider/actions/workflows/macos.yml)
[![oqs-provider](https://circleci.com/gh/open-quantum-safe/oqs-provider.svg?style=svg)](https://app.circleci.com/pipelines/github/open-quantum-safe/oqs-provider)

oqsprovider - Open Quantum Safe provider for OpenSSL (3.x)
==========================================================

Purpose
-------

This repository contains code to enable quantum-safe cryptography (QSC)
in a standard OpenSSL (3.x) distribution by way of implementing a single
shared library, the OQS
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html).

Status
------

Currently this provider fully enables quantum-safe cryptography for KEM
key establishment in TLS1.3 including management of such keys via the
OpenSSL (3.0) provider interface and hybrid KEM schemes. Also, QSC
signatures including CMS and CMP functionality are available via the OpenSSL
EVP interface. Key persistence is provided via the encode/decode
mechanism and X.509 data structures. Starting with OpenSSL 3.2 support for 
TLS1.3 signature functionality is available and final glitches for CMS
have been resolved.

The standards implemented are documented in the separate file [STANDARDS.md](STANDARDS.md).

Algorithms
----------

This implementation makes available the following quantum safe algorithms:

<!--- OQS_TEMPLATE_FRAGMENT_ALGS_START -->
### KEM algorithms

- **BIKE**: `bikel1`, `p256_bikel1`, `x25519_bikel1`, `bikel3`, `p384_bikel3`, `x448_bikel3`, `bikel5`, `p521_bikel5`
- **CRYSTALS-Kyber**: `kyber512`, `p256_kyber512`, `x25519_kyber512`, `kyber768`, `p384_kyber768`, `x448_kyber768`, `x25519_kyber768`, `p256_kyber768`, `kyber1024`, `p521_kyber1024`
- **FrodoKEM**: `frodo640aes`, `p256_frodo640aes`, `x25519_frodo640aes`, `frodo640shake`, `p256_frodo640shake`, `x25519_frodo640shake`, `frodo976aes`, `p384_frodo976aes`, `x448_frodo976aes`, `frodo976shake`, `p384_frodo976shake`, `x448_frodo976shake`, `frodo1344aes`, `p521_frodo1344aes`, `frodo1344shake`, `p521_frodo1344shake`
- **HQC**: `hqc128`, `p256_hqc128`, `x25519_hqc128`, `hqc192`, `p384_hqc192`, `x448_hqc192`, `hqc256`, `p521_hqc256`†

### Signature algorithms

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
TLS operations. This designation [can be changed by modifying the
"enabled" flags in the main algorithm configuration file](CONFIGURE.md#pre-build-configuration).

In order to support parallel use of classic and quantum-safe cryptography 
this provider also provides different hybrid algorithms, combining classic
and quantum-safe methods: These are listed above with a prefix denoting a
classic algorithm, e.g., for elliptic curve: "p256_".

A full list of algorithms, their interoperability code points and OIDs as well
as a method to dynamically adapt them, e.g., for interoperability testing are
documented in [ALGORITHMS.md](ALGORITHMS.md).

Building and testing -- Quick start
-----------------------------------

All component builds and testing described in detail below can be executed by
running the scripts `scripts/fullbuild.sh` and `scripts/runtests.sh`
respectively (tested on Linux Ubuntu and Mint as well as MacOS).

By default, these scripts always build and test against the current OpenSSL `master` branch.

These scripts can be [configured by setting various variables](CONFIGURE.md#convenience-build-script-options). Please note that these scripts do _not_ install `oqsprovider`. This can be facilitated by running `cmake --install _build` (and following the [activation instructions](USAGE.md#activation).

Building and testing
--------------------

The below describes the basic build-test-install cycle using the standard
`cmake` tooling. Platform-specific notes are available for [UNIX](NOTES-UNIX.md)
(incl. MacOS and `cygwin`) and [Windows](NOTES-Windows.md).

## Configuration options

All options to configure `oqs-provider` at build- or run-time are documented
in [CONFIGURE.md](CONFIGURE.md).

## Pre-requisites

To be able to build `oqsprovider`, OpenSSL 3.0 and liboqs need to be installed.
It's not important where they are installed, just that they are. If installed
in non-standard locations, these must be provided when running `cmake` via
the variables "OPENSSL_ROOT_DIR" and "liboqs_DIR". See [CONFIGURE.md](CONFIGURE.md)
for details.

## Basic steps

    cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && cmake --install _build
    
Using
-----

Usage of `oqsprovider` is documented in the separate [USAGE.md](USAGE.md) file.

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

For [general OpenSSL implementation limitations, e.g., regarding provider feature usage and support,
see here](https://wiki.openssl.org/index.php/OpenSSL_3.0#STATUS_of_current_development).

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
- Will Childs-Klein
- Thomas Bailleux

History
-------

Documentation on current and past releases ("code history") is documented in
the separate file [RELEASE.md](RELEASE.md).

Acknowledgments
---------------

The `oqsprovider` project is supported through the [NGI Assure Fund](https://nlnet.nl/assure),
a fund established by [NLnet](https://nlnet.nl) with financial
support from the European Commission's [Next Generation Internet programme](https://www.ngi.eu),
under the aegis of DG Communications Networks, Content and Technology
under grant agreement No 957073.

Financial support for the development of Open Quantum Safe has been provided
by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

The OQS project would like to make a special acknowledgement to the companies who
have dedicated programmer time to contribute source code to OQS, including
Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been
supported by various research grants, including funding from the Natural
Sciences and Engineering Research Council of Canada (NSERC); see
[here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and
[here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf)
for funding acknowledgments.

# Disclaimers

## Standard software disclaimer

THIS SOFTWARE IS PROVIDED WITH NO WARRANTIES, EXPRESS OR IMPLIED, AND
ALL IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING ANY WARRANTY OF
MERCHANTABILITY AND WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE.

## Component disclaimer

[liboqs disclaimer](https://github.com/open-quantum-safe/liboqs#limitations-and-security)
