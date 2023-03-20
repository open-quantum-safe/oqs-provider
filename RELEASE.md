oqs-provider 0.5.0-dev
======================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.  

**oqs-provider** is a standalone prototype [OpenSSL 3](https://github.com/openssl/openssl) [provider](https://www.openssl.org/docs/manmaster/man7/provider.html) enabling [liboqs](https://github.com/open-quantum-safe/liboqs)-based quantum-safe and hybrid key exchange for TLS 1.3, as well as quantum-safe and hybrid X.509 certificate generation, CMS ond dgst operations. 

When deployed, the `oqs-provider` binary (shared library) thus adds support for quantum-safe cryptographic operations to any standard OpenSSL(v3) installation.

In general, the oqs-provider `main` branch is meant to be useable in conjunction with the `main` branch of [liboqs](https://github.com/open-quantum-safe/liboqs) and the `master` branch of [OpenSSL](https://github.com/openssl/openssl).

Further details on building, testing and use can be found in [README.md](https://github.com/open-quantum-safe/oqs-provider/blob/main/README.md). See in particular limitations on intended use.

Release notes
=============

This is the development pre-release version 0.5.0 of oqs-provider.

Security considerations
-----------------------

None.

What's New
----------

This release continues from the 0.4.0 release of oqs-provider and is fully tested to be used in conjunction with the main branch of [liboqs](https://github.com/open-quantum-safe/liboqs). 

oqs-provider now also enables use of QSC algorithms during TLS1.3 handshake. The required OpenSSL code updates are contained in https://github.com/openssl/openssl/pull/19312. Prior to this code merging, the functionality can be tested by using https://github.com/baentsch/openssl/tree/sigload.

### Algorithm updates

None.

### Functional updates

- Enablement of oqs-provider as a (first) dynamically fetchable OpenSSL3 TLS1.3 signature provider.

### Misc updates

- Dynamic code point and OID changes via environment variables. See [ALGORITHMS.md](ALGORITHMS.md).
- Dynamic key encoding changes via environment variable using external qsc_key_encoder library. See [ALGORITHMS.md](ALGORITHMS.md).

---

Previous Release Notes
======================

This is version 0.4.0 of oqs-provider.

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

