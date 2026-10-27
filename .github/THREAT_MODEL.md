# oqs-provider Security Threat Model

This document describes the security boundaries that `oqsprovider` expects
researchers, contributors, and automated agents to use when evaluating possible
vulnerabilities. It complements [`SECURITY.md`](../SECURITY.md),
[`README.md`](../README.md), [`CONFIGURE.md`](../CONFIGURE.md),
[`ALGORITHMS.md`](../ALGORITHMS.md), and [`STANDARDS.md`](../STANDARDS.md).

The purpose is practical triage: a good report explains which boundary is
crossed, how the issue is reachable through the OpenSSL provider interface, what
evidence reproduces it, and why it is a defect in `oqsprovider` itself rather
than in one of its dependencies, a known limitation, or a caller error.

## Project Security Role

`oqsprovider` is an [OpenSSL provider](https://docs.openssl.org/master/man7/provider/):
a module loaded by `libcrypto` that exposes post-quantum and hybrid
post-quantum/traditional KEMs, signatures, and key management to any application
using OpenSSL. It requires **OpenSSL version 3.0 or later (including the 4.x
series)** and does **not** implement cryptographic primitives itself. The
post-quantum primitives come from
[liboqs](https://github.com/open-quantum-safe/liboqs) ("downwards"), and the
traditional primitives, ASN.1/X.509/PKCS#8/CMS handling, and TLS plumbing come
from OpenSSL's `libcrypto`/`libssl` ("upwards").

`oqsprovider` is therefore glue and composition code. Its security value is in
handling attacker-influenced data safely as it crosses between an application
(often a TLS peer or a certificate/key file) and the two libraries it bridges.
It is normally embedded in a larger application, so a "remote attacker" is
usually remote to that application (for example, a TLS client or server, or the
supplier of a certificate, key, or signature) rather than remote to the provider
as a standalone service.

The provider is invoked by the OpenSSL core through the provider dispatch
mechanism. The core is assumed to honour the provider API contract: it calls
provider functions with the documented argument types, obeys returned lengths,
and manages object lifetimes as specified. `oqsprovider` cannot defend against a
`libcrypto` that violates its own provider contract. Within that assumption,
`oqsprovider` is responsible for safely handling the byte contents, explicit
lengths, `OSSL_PARAM` values, serialized encodings, and algorithm identifiers
that ultimately originate from untrusted sources.

## What Is Explicitly Out Of Scope: Dependencies

As stated in [`SECURITY.md`](../SECURITY.md), incorrect, weak, or vulnerable
cryptographic algorithm *implementations* provided by
[liboqs](https://github.com/open-quantum-safe/liboqs) or by OpenSSL's
`libcrypto` are **not** vulnerabilities in this project. This includes:

- Cryptanalytic weakness of a post-quantum algorithm.
- A memory-safety or constant-time defect inside a `liboqs` primitive
  (`OQS_KEM_*`, `OQS_SIG_*`) or inside an OpenSSL primitive.
- A bug reachable only through a `liboqs` or `libcrypto` API that `oqsprovider`
  calls correctly.

Such issues must be reported to the respective upstream project. A report is
in scope for `oqsprovider` only when the defect is in the provider's own logic —
how it parses, composes, validates, allocates, frees, or dispatches — including
calling an upstream API incorrectly (wrong length, ignored return value, wrong
buffer) in a way that a correct upstream cannot defend against.

## Protected Assets And Security Goals

- Secret keys and secret-derived material (private keys, KEM shared secrets,
  seeds, hybrid private components) passed to/from `liboqs` and `libcrypto`.
- Memory safety of every provider entry point reachable from `libcrypto`:
  key management, encoders, decoders, signature, KEM, and key-exchange
  dispatch functions.
- Correct rejection of malformed or malicious serialized inputs: X.509
  `SubjectPublicKeyInfo`, PKCS#8 `PrivateKeyInfo`, raw public/private key
  buffers, signatures, KEM ciphertexts, PEM/DER, and algorithm identifiers/OIDs.
- Correct handling of the hybrid composition format (see below): the
  length-prefixed concatenation of a traditional and a post-quantum component.
- Correct signature verification and KEM decapsulation semantics as surfaced
  through the provider (no acceptance of a signature under the wrong component,
  parameter set, or composition; correct success/failure status).
- Cleansing of secret-derived material when a key object is freed.
- Correct registration of TLS groups and signature algorithms so that a
  negotiated hybrid does not silently degrade to only its traditional or only
  its post-quantum half.

## Trust Boundaries

### Decode / Parse Boundary (highest value)

The decoders ([`oqsprov/oqs_decode_der2key.c`](../oqsprov/oqs_decode_der2key.c)
and the key-loading functions in
[`oqsprov/oqsprov_keys.c`](../oqsprov/oqsprov_keys.c)) turn attacker-supplied
bytes — a certificate, a public key, a PKCS#8 private key, a PEM/DER blob — into
internal key objects. Every byte here is untrusted, including any embedded
length, count, or OID. `oqsprovider` must not read past supplied lengths, trust
an embedded length field, or accept malformed or cross-parameter encodings.

### Hybrid Composition Boundary

Hybrid keys, signatures, and KEM shares are encoded as a **simple concatenation**
of a traditional and a post-quantum component (see [`STANDARDS.md`](../STANDARDS.md)).
For key material the traditional component is prefixed with a 4-byte big-endian
length. That length prefix and the overall buffer length are attacker-controlled
at the parse boundary: a report that shows a mismatch between the declared
classical length and the actual buffer size leading to an out-of-bounds
read/write, an under-read, or acceptance of a malformed hybrid is in scope.
Splitting and reassembling the components is a core part of this boundary.

### Provider Dispatch Boundary

`libcrypto` drives the provider through `OSSL_DISPATCH` tables and passes data as
`OSSL_PARAM` arrays and pointer/length pairs. Provider code must validate the
presence, type, and size of parameters it consumes and must honour the OpenSSL
convention for size queries (a `NULL` output buffer requesting a length). Treat
the *contents* of these buffers as untrusted even though the *caller*
(`libcrypto`) is trusted to follow the ABI.

### liboqs Boundary ("downwards")

`oqsprovider` calls `liboqs` with buffers it has sized from its own metadata.
Passing a buffer shorter than the algorithm requires, ignoring an `OQS_STATUS`
return, or reusing state incorrectly is an `oqsprovider` defect even though the
crash surfaces inside `liboqs`. A weakness *within* the `liboqs` primitive is not.

### libcrypto Boundary ("upwards")

`oqsprovider` calls OpenSSL for traditional primitives and ASN.1. Mishandling an
OpenSSL return value, object, or error (for example, using an `EVP_PKEY` that
failed to construct, or leaking/double-freeing an OpenSSL object) is an
`oqsprovider` defect. A bug inside `libcrypto` itself is not.

## In-Scope Vulnerability Classes

Reachable through a supported build and backed by a working reproducer:

### Memory Safety
- Out-of-bounds read/write in decoders, encoders, or hybrid split/join logic.
- Use-after-free, double free, invalid free, or uninitialized-memory use in key
  management and the key duplication/loading paths.
- Integer overflow/truncation on a length, count, or size field that leads to
  memory corruption, invalid acceptance, or wrong output length.
- NULL-pointer dereference reachable through a provider entry point with
  attacker-controlled input (a malformed key/cert that a well-behaved
  application feeds to OpenSSL).

### Cryptographic API Correctness
- A verifier accepting a signature that is invalid, from the wrong component,
  wrong parameter set, or a non-canonical/malformed hybrid encoding.
- A KEM accepting a malformed public key or ciphertext in a way that breaks the
  expected security or canonicalization contract.
- Wrong success/failure status returned to a caller that relies on it before
  using generated output.
- Mismatched public/secret key metadata, OIDs, or algorithm identifiers leading
  to unsafe behavior or a silent hybrid downgrade.

### Secret Material Lifetime
- Private keys, shared secrets, seeds, or secret-derived intermediates left in
  reusable memory after a key is freed or after an error path, with a realistic
  observation or reuse path. A missing cleanse call *alone* is a hardening lead,
  not a confirmed vulnerability: identify the secret source, the intended
  cleanup boundary, the residual bytes, and how they are observed or reused.

### Denial Of Service
- A crash, unbounded allocation, or excessive resource use triggered by an
  ordinary application feeding attacker-controlled input (a certificate,
  key, TLS handshake message, signature, or ciphertext) through OpenSSL into the
  provider. Describe the attacker-controlled input and the deployment path
  (loading a cert, verifying a signature, TLS handshake, decapsulation, key
  decode).

## Out-Of-Scope Or Usually Non-Vulnerabilities

- Weakness, cryptanalysis, or implementation defects of a post-quantum algorithm
  itself, or any bug inside [liboqs](https://github.com/open-quantum-safe/liboqs)
  or `libcrypto` (report upstream — such reports opened here are closed
  immediately, per [`SECURITY.md`](../SECURITY.md)).
- Reports that only state that a post-quantum algorithm may someday be broken.
- Physical, power/EM, fault-injection (including Rowhammer), and CPU/hardware
  side channels.
- Timing/side-channel claims about the underlying primitives: constant-time
  behavior of the KEM/signature math is a `liboqs`/`libcrypto` responsibility.
  A provider-level timing claim must trace secret data to a branch or memory
  access *in `oqsprovider`'s own code*, not in a primitive it calls.
- Claims based only on source pattern matching with no reachable PoC, test, or
  sanitizer evidence through a provider entry point.
- Crashes that require a caller (application or `libcrypto`) to violate the
  documented provider/OpenSSL API contract (for example, passing a pointer that
  does not reference a region of the claimed size).
- Missing-zeroization claims with no secret-derived dataflow, no intended
  cleanup boundary, or no realistic observation path.
- Vulnerabilities solely in a downstream application that misuses OpenSSL or the
  provider despite a clear contract.
- Behavior only reproducible with a non-default or experimental build option
  (for example [`OQS_KEM_ENCODERS`](../CONFIGURE.md#oqs_kem_encoders) or
  [`NOPUBKEY_IN_PRIVKEY`](../CONFIGURE.md#nopubkey_in_privkey), whose OIDs are
  chosen at random) without saying so and explaining the realistic deployment.

Note that `oqsprovider` "is not meant for productive use"
([`SECURITY.md`](../SECURITY.md)); severity should be assessed accordingly, and
most valid findings are best handled by a public issue and/or a fix PR rather
than an embargoed CVE.

## Platform And Algorithm Priority

The project's purpose is to serve **novel, experimental, and community**
post-quantum algorithms. Standardized algorithms (ML-KEM, ML-DSA, SLH-DSA, and
similar) are already well supported by OpenSSL itself and by other projects, so
they receive comparatively little added value here and are candidates for removal
to reduce the maintenance and vulnerability surface (see
[issue #821](https://github.com/open-quantum-safe/oqs-provider/issues/821)).
Prioritize accordingly:

- **Experimental and community algorithms deserve the most scrutiny**: they are
  less well exercised elsewhere and are the reason this project exists. A defect
  in their provider-side handling is more likely to be novel and actionable here.
- The **generic provider logic** — encoders, decoders, hybrid composition, key
  management, and TLS group/signature registration — is algorithm-independent and
  is the highest-value target regardless of the specific algorithm, because one
  defect affects many algorithms at once.
- Findings that exist *only* in a standardized algorithm's handling are lower
  priority: the affected code may be removed rather than patched, and the same
  algorithm is better maintained upstream.
- Prioritize the platforms exercised in
  [CI](workflows) (Linux x86_64 with the AddressSanitizer "Security
  checks" job, plus macOS and Windows). A finding on another platform should
  explain whether it also affects a CI-covered platform.
- Identify the affected OpenSSL version. `oqsprovider` supports OpenSSL 3.0 and
  later (including 4.x), and provider behavior can vary across those versions.

## Report Quality Requirements

A security report should include:

- Repository commit/branch and the exact build options.
- OpenSSL version (must be 3.0 or later, including 4.x),
  [liboqs](https://github.com/open-quantum-safe/liboqs) version/branch, compiler,
  sanitizer, OS, CMake, and (if relevant) the OpenSSL configuration.
- A threat-model statement: attacker capability, boundary crossed, and why the
  defect is in `oqsprovider` rather than in `liboqs`, `libcrypto`, or the caller.
- The affected provider entry point (keymgmt/encoder/decoder/signature/KEM/
  keyexch), algorithm family, parameter set, and a representative source
  location.
- A minimal PoC or failing regression test that exercises the issue through the
  provider (ideally via the OpenSSL API or a test binary), and the exact build
  and run commands from a clean checkout.
- Sanitizer output (AddressSanitizer is the primary detector here), plus
  expected vulnerable and fixed behavior.
- Impact stated without exaggeration, distinguishing memory safety, DoS,
  signature/KEM acceptance, hybrid mishandling, and secret-lifetime issues.
- A suggested fix and regression test where possible.

Do not submit a report that has not been built and run unless it is explicitly
labeled an unverified hypothesis.

## Triage Checklist For Researchers

1. Which provider boundary is crossed — decode/parse, hybrid composition,
   provider dispatch, the `liboqs` call boundary, or the `libcrypto` call
   boundary?
2. Is the defect in `oqsprovider`'s own logic, or does it actually live in
   `liboqs` or `libcrypto` (and therefore belong upstream)?
3. What attacker controls the input — certificate, key file, signature,
   ciphertext, TLS message, `OSSL_PARAM`, or build configuration?
4. Does the reproducer reach the code through a real provider entry point under
   the documented OpenSSL/provider API contract, on OpenSSL 3.0 or later?
5. Is the affected algorithm experimental/community (higher priority) or
   standardized (lower priority, possibly slated for removal)? Is a non-default
   build option required?
6. Does a clean build reproduce it with the provided commands, and does a
   detector (AddressSanitizer, a KAT/interop failure, a wrong verify/decaps
   result) give concrete evidence?
7. Is it already covered by an existing test, open issue, or a known upstream
   advisory?
8. Is this a vulnerability, a hardening opportunity, a test gap, or a
   documentation issue?

If any answer is unknown, state the uncertainty in the report rather than filling
the gap with speculation.
