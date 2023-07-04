Usage instructions for oqsprovider
==================================

This file documents information required to properly utilize `oqsprovider`
after installation on a machine running `openssl` v3.

Beware that `oqsprovider` will not work on machines where an OpenSSL
version below "3.0.0" is (the default) installed.

## Baseline assumption

An `openssl` version >= 3.0.0 is available and set in the "PATH" environment
variable such as that the command `openssl version` yields a result documenting
this, e.g., as follows:

```
OpenSSL 3.2.0-dev  (Library: OpenSSL 3.2.0-dev )
```

## Activation

Every OpenSSL provider needs to be activated for use. There are two main ways
for this:

### Explicit command line option

#### -provider

Most `openssl` commands permit passing the option `-provider`: The name after
this command is that of the provider to be activated.

As an example: `openssl list -signature-algorithms -provider oqsprovider`
outputs all quantum safe signature algorithms made available for `openssl` use.

#### -provider-path

All `openssl` commands accepting `-provider` also permit passing `-provider-path`
as a possibility to reference the location in the local filesystem where the
provider binary is located. This is of particular use if the provider did not
(yet) get installed in the system location, which typically is in `lib/ossl-modules`
in the main `openssl` installation tree.

### Configuration file

As an alternative to passing command line parameters, providers can be activated
for general use by adding instructions to the `openssl.cnf` file. In the case of
`oqs-provider` add these lines to achieve this:

```
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[oqsprovider_sect]
activate = 1
```

#### module option

Next to the "activate" keyword, `openssl` also recognizes the "module" keyword
which mirrors the functionality of `-provider-path` documented above: This way,
a non-standard location for the `oqsprovider` shared library (.SO/.DYLIB/.DLL)
can be registered for testing.

If this configuration variable is not set, the global environment variable
"OPENSSL_MODULES" must point to a directory where the `oqsprovider` binary
is to be found. 

If the `oqsprovider` binary cannot be found, it simply (and silently) will
not be available for use.

#### System wide installation

The system-wide `openssl.cnf` file is typically located at (operating system dependent):
- /etc/ssl/ (UNIX/Linux)
- /opt/homebrew/etc/openssl@3/ (MacOS Homebrew on Apple Silicon)
- /usr/local/etc/openssl@3/ (MacOS Homebrew on Intel Silicon)
- C:\Program Files\Common Files\SSL\ (Windows)

Adding `oqsprovider` to this file will enable its seamless operation alongside other
`openssl` providers. If successfully done, running, e.g., `openssl list -providers`
should output something along these lines (version IDs variable of course):

```
providers:
  default
    name: OpenSSL Default Provider
    version: 3.1.1
    status: active
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.5.0
    status: active
```

If this is the case, all `openssl` commands can be used as usual, extended
by the option to use quantum safe cryptographic algorithms in addition/instead
of classical crypto algorithms.

This configuration is the one used in all examples below.

*Note*: Be sure to always activate either the "default" or "fips" provider as these
deliver functionality also needed by `oqsprovider` (e.g., for hashing or high
quality random data during key generation).

## Checking provider version information

    openssl list -providers -verbose 

## Checking quantum safe signature algorithms available for use

    openssl list -signature-algorithms -provider oqsprovider 

## Checking quantum safe KEM algorithms available for use

    openssl list -kem-algorithms -provider oqsprovider 

## Creating keys and certificates

This can be facilitated for example by using the usual `openssl` commands:

    openssl req -x509 -new -newkey rsa -keyout rsa_CA.key -out rsa_CA.crt -nodes -subj "/CN=test CA" -days 365 -config openssl/apps/openssl.cnf
    openssl genpkey -algorithm rsa -out rsa_srv.key
    openssl req -new -newkey rsa -keyout rsa_srv.key -out rsa_srv.csr -nodes -subj "/CN=test server" -config openssl/apps/openssl.cnf
    openssl x509 -req -in rsa_srv.csr -out rsa_srv.crt -CA rsa_CA.crt -CAkey rsa_CA.key -CAcreateserial -days 365

These examples create classic RSA keys but the very same commands can be used
to create PQ certificates replacing the key type "rsa" with any of the PQ
signature algorithms [listed above](#signature-algorithms).

## Setting up a (quantum-safe) test server

A simple server utilizing PQ/quantum-safe KEM algorithms and classic RSA
certicates can be set up for example by running

    openssl s_server -cert rsa_srv.crt -key rsa_srv.key -www -tls1_3 -groups kyber768:frodo640shake

## Running a client to interact with (quantum-safe) KEM algorithms

This can be facilitated for example by running

    openssl s_client -groups frodo640shake

By issuing the command `GET /` the quantum-safe crypto enabled OpenSSL3
server returns details about the established connection.

Any [available quantum-safe/PQ KEM algorithm](#kem-algorithms) can be selected by passing it in the `-groups` option.

## S/MIME message signing -- Cryptographic Message Syntax (CMS)

Also possible is the creation and verification of quantum-safe digital
signatures using [CMS](https://datatracker.ietf.org/doc/html/rfc5652).

#### Signing data

For creating signed data, two steps are required: One is the creation
of a certificate using a QSC algorithm; the second is the use of this
certificate (and its signature algorithm) to create the signed data:

Step 1: Create quantum-safe key pair and self-signed certificate:

    openssl req -x509 -new -newkey dilithium3 -keyout qsc.key -out qsc.crt -nodes -subj "/CN=oqstest" -days 365 -config openssl/apps/openssl.cnf

By changing the `-newkey` parameter algorithm name [any of the 
supported quantum-safe or hybrid algorithms](#signature-algorithms)
can be utilized instead of the sample algorithm `dilithium3`.

Step 2: Sign data:

As
[the CMS standard](https://datatracker.ietf.org/doc/html/rfc5652#section-5.3)
requires the presence of a digest algorithm, while quantum-safe crypto
does not, in difference to the QSC certificate creation command above,
passing a message digest algorithm via the `-md` parameter is mandatory.

    openssl cms -in inputfile -sign -signer qsc.crt -inkey qsc.key -nodetach -outform pem -binary -out signedfile -md sha512

Data to be signed is to be contained in the file named `inputfile`. The
resultant CMS output is contained in file `signedfile`. The QSC algorithm
used is the same signature algorithm utilized for signing the certificate
`qsc.crt`.

#### Verifying data

Continuing the example above, the following command verifies the CMS file
`signedfile` and outputs the `outputfile`. Its contents should be identical
to the original data in `inputfile` above.

    openssl cms -verify -CAfile qsc.crt -inform pem -in signedfile -crlfeol -out outputfile 

Note that it is also possible to build proper QSC certificate chains
using the standard OpenSSL calls. For sample code see
[scripts/oqsprovider-certgen.sh](scripts/oqsprovider-certgen.sh).

### Support of `dgst` (and sign)

Also tested to operate OK is the [openssl dgst](https://www.openssl.org/docs/man3.0/man1/openssl-dgst.html)
command. Sample invocations building on the keys and certificate files in the examples above:

#### Signing

    openssl dgst -sign qsc.key -out dgstsignfile inputfile

#### Verifying

    openssl dgst -signature dgstsignfile -verify qsc.pubkey inputfile

The public key can be extracted from the certificate using standard openssl command:

    openssl x509 -in qsc.crt -pubkey -noout > qsc.pubkey

The `dgst` command is not tested for interoperability with [oqs-openssl111](https://github.com/open-quantum-safe/openssl).

*Note on KEM Decapsulation API*:

The OpenSSL [`EVP_PKEY_decapsulate` API](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decapsulate.html) specifies an explicit return value for failure. For security reasons, most KEM algorithms available from liboqs do not return an error code if decapsulation failed. Successful decapsulation can instead be implicitly verified by comparing the original and the decapsulated message.

