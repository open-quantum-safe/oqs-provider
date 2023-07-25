# oqs-provider 0.5.2-dev

## About

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**oqs-provider** is a standalone [OpenSSL 3](https://github.com/openssl/openssl) [provider](https://www.openssl.org/docs/manmaster/man7/provider.html) enabling [liboqs](https://github.com/open-quantum-safe/liboqs)-based quantum-safe and hybrid key exchange for TLS 1.3, as well as quantum-safe and hybrid X.509 certificate generation, CMS and dgst operations.

When deployed, the `oqs-provider` binary (shared library) thus adds support for quantum-safe cryptographic operations to any standard OpenSSL(v3) installation.

In general, the oqs-provider `main` branch is meant to be useable in conjunction with the `main` branch of [liboqs](https://github.com/open-quantum-safe/liboqs) and the `master` branch of [OpenSSL](https://github.com/openssl/openssl).

Further details on building, testing and use can be found in [README.md](https://github.com/open-quantum-safe/oqs-provider/blob/main/README.md). See in particular limitations on intended use.

## Release notes

This is version 0.5.2-dev of oqs-provider.

### Security considerations

None.

### What's New

This release continues from the 0.5.1 release of oqs-provider and is fully tested to be used in conjunction with the main branch of [liboqs](https://github.com/open-quantum-safe/liboqs). This code is in sync with `liboqs` "main" branch.

### Additional new feature highlights

Previous Release Notes
======================

## This is version 0.5.1 of oqs-provider.

### Security considerations

None.

### What's New

This release continues from the 0.5.0 release of oqs-provider and is fully tested to be used in conjunction with the main branch of [liboqs](https://github.com/open-quantum-safe/liboqs). This release is guaranteed to be in sync with v0.8.0 of `liboqs`.

### Additional new feature highlights

- Support for Windows platform
- Added `brew` support for MacOS
- Documentation restructured supporting different platforms
- Enable statically linkable oqsprovider

#### What's Changed (full commit list)

* trigger oqs-demos build when pushing to main by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/182
* Enable building on platforms without _Atomic support by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/183
* Standalone ctest by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/184
* Convert oqs-kem-info.md code points to hex by @WillChilds-Klein in https://github.com/open-quantum-safe/oqs-provider/pull/188
* Documentation update by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/187
* Add full Windows support by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/192
* Improve installation by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/196
* document specs [skip ci] by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/190
* Add .DS_Store (macOS), .vscode (visual studio code), and .idea (Jetbr… by @planetf1 in https://github.com/open-quantum-safe/oqs-provider/pull/200
* first test for macos CI by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/198
* Add brew to preinstall test matrix by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/205
* General documentation overhaul by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/204
* change TLS demo to use QSC alg [skip ci] by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/208
* Build a module instead of a shared library. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/207
* explain groups in USAGE [skip ci] by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/214
* ensure OpenSSL3 is linked to liboqs during script build by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/212
* Remove trailing whitespaces in generated code. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/215
* Fix a minor bug in the `runtests.sh`. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/216
* Specify version `3.1` while installing OpenSSL using brew. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/217
* Allow the user to build oqs-provider as a static library. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/201
* Add a line to `RELEASE.md` to highlight the support for static libraries by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/220
* Enhance github bug report template by @baentsch in https://github.com/open-quantum-safe/oqs-provider/pull/219
* Use OpenSSL 3 if available to build liboqs on CircleCI/macOS. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/222
* Fix a bug in the CMake script. by @thb-sb in https://github.com/open-quantum-safe/oqs-provider/pull/221

#### New Contributors

* @WillChilds-Klein made their first contribution in https://github.com/open-quantum-safe/oqs-provider/pull/188
* @planetf1 made their first contribution in https://github.com/open-quantum-safe/oqs-provider/pull/200
* @thb-sb made their first contribution in https://github.com/open-quantum-safe/oqs-provider/pull/207

**Full Changelog**: https://github.com/open-quantum-safe/oqs-provider/compare/0.5.0...0.5.1

## This is version 0.5.0 of oqs-provider.

Security considerations
-----------------------

None.

What's New
----------

This release continues from the 0.4.0 release of oqs-provider and is fully tested to be used in conjunction with the main branch of [liboqs](https://github.com/open-quantum-safe/liboqs). This release is guaranteed to be in sync with v0.8.0 of `liboqs`.

oqs-provider now also enables use of QSC algorithms during TLS1.3 handshake. The required OpenSSL code updates are contained in https://github.com/openssl/openssl/pull/19312. Prior to this code merging, the functionality can be tested by using https://github.com/baentsch/openssl/tree/sigload.

### Algorithm updates

All algorithms no longer supported in the [NIST PQC competition](https://csrc.nist.gov/projects/post-quantum-cryptography) and not under consideration for standardization by ISO have been removed. All remaining algorithms with the exception of McEliece have been lifted to their final round 3 variants as documented in [liboqs](https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md#release-notes). Most notably, algorithm names for Sphincs+ have been changed to the naming chosen by its authors.

### Functional updates

- Enablement of oqs-provider as a (first) dynamically fetchable OpenSSL3 TLS1.3 signature provider.
- MacOS support
- Full support for CA functionality
- Algorithms can now be selected by their respective bit strength using the property string "oqsprovider.security_bits"
- Documentation of (O)IDs used by the different PQC algorithms used and supported in current and past releases of oqs-openssl and oqs-provider
- Testing is now completely independent of a source code distribution of OpenSSL being available
- oqsprovider can be built and installed making use of pre-existing installations of `OpenSSL` and `liboqs`. Details are found in the "scripts" directory's build and test scripts.
- Automated creation of (Debian) packaging information
- Graceful handling (by way of functional degradation) of the feature sets contained in different OpenSSL releases; all oqsprovider capabilities are only available when using a version > than OpenSSL3.1.
- A bug regarding handling of hybrid algorithms has been fixed as well as some memory leaks.

### Misc updates

- Dynamic code point and OID changes via environment variables. See [ALGORITHMS.md](ALGORITHMS.md).
- Dynamic key encoding changes via environment variable using external qsc_key_encoder library. See [ALGORITHMS.md](ALGORITHMS.md).

---

**Full Changelog**: https://github.com/open-quantum-safe/oqs-provider/compare/0.4.0...0.5.0.

## This is version 0.4.0 of oqs-provider.

Security considerations
-----------------------

This release removes Rainbow level 1 and all variants of SIDH and SIKE due to cryptanalytic breaks of those algorithms.  Users are advised to move away from use of those algorithms immediately.

What's New
----------

This release continues from the 0.3.0 release of oqs-provider and is fully tested to be used in conjunction with version 0.7.2 of [liboqs](https://github.com/open-quantum-safe/liboqs).

oqs-provider has been integrated as an external test component for [OpenSSL3 testing](https://github.com/openssl/openssl/blob/master/test/README-external.md#oqsprovider-test-suite) and will thus remain in line with any possibly required provider API enhancements.

### Algorithm updates

- Removal of SIKE/SIDH and Rainbow level I due to cryptographic breaks

### Functional updates

- Addition of quantum-safe CMS operations via the [OpenSSL interface](https://www.openssl.org/docs/man3.0/man1/openssl-cms.html)
- Addition of quantum-safe dgst operations via the [OpenSSL interface](https://www.openssl.org/docs/man3.0/man1/openssl-dgst.html)

### Misc updates

- Additional testing
- Integration with and of OpenSSL test harness

---

**Full Changelog**: https://github.com/open-quantum-safe/oqs-provider/compare/0.3.0...0.4.0.

## 0.3.0 - January 2022

## About

This is the first official release of `oqsprovider`, a plugin/shared library making available quantum safe cryptography (QSC) to [OpenSSL (3)](https://www.openssl.org/) installations via the [provider](https://www.openssl.org/docs/manmaster/man7/provider.html) API. Work on this project began in [oqs-openssl](https://github.com/open-quantum-safe/openssl)'s branch "OQS-OpenSSL3" by [@baentsch](https://github.com/baentsch). This original code dependent on OpenSSL APIs was transferred into a standalone project by [@levitte](https://github.com/levitte) and subsequently branched by the OQS project into this code base.

This project is part of the **Open Quantum Safe (OQS) project**: More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

## Release Notes

The current feature set of `oqsprovider` comprises

- support of all QSC KEM algorithms contained in [liboqs](https://github.com/open-quantum-safe/liboqs) ([v.0.7.1](https://github.com/open-quantum-safe/liboqs/releases/tag/0.7.1)) including hybrid classic/QSC algorithm pairs
- integration of all QSC KEM algorithms into TLS 1.3 using the [groups interface](https://github.com/open-quantum-safe/oqs-provider#running-a-client-to-interact-with-quantum-safe-kem-algorithms)
- support of all QSC signature algorithms contained in [liboqs](https://github.com/open-quantum-safe/liboqs) ([v.0.7.1](https://github.com/open-quantum-safe/liboqs/releases/tag/0.7.1)) including hybrid classic/QSC algorithm pairs
- integration for persistent data structures (X.509) of all QSC signature algorithms using the [standard OpenSSL toolset](https://github.com/open-quantum-safe/oqs-provider#creating-classic-keys-and-certificates)

### Limitations

- This code is [not meant to be used in productive deployments](https://openquantumsafe.org/liboqs/security)
- Currently, only Linux is supported and only Ubuntu 20/x64 is tested
- Full TLS1.3 support for QSC signatures is missing (see https://github.com/openssl/openssl/issues/10512)
