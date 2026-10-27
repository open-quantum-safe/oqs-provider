# Instructions For Security Researchers And Automated Agents

This repository is `oqsprovider`, an
[OpenSSL provider](https://docs.openssl.org/master/man7/provider/) written in C
that bridges post-quantum and hybrid post-quantum/traditional algorithms from
[liboqs](https://github.com/open-quantum-safe/liboqs) into OpenSSL. It requires
**OpenSSL version 3.0 or later (including the 4.x series)** and does not implement
cryptographic primitives itself.

Low-quality reports waste scarce maintainer time. Do not submit a security
finding until you have read the threat model, built the affected configuration,
reproduced the issue through a real provider entry point, and confirmed it is a
defect in `oqsprovider` itself rather than in one of its dependencies.

Start here:

- [`.github/THREAT_MODEL.md`](THREAT_MODEL.md)
- [`SECURITY.md`](../SECURITY.md)
- [`README.md`](../README.md) and [`USAGE.md`](../USAGE.md)
- [`CONFIGURE.md`](../CONFIGURE.md)
- [`ALGORITHMS.md`](../ALGORITHMS.md)
- [`STANDARDS.md`](../STANDARDS.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`test/README.md`](../test/README.md)

## Security Handling

Do not publicly disclose a plausible vulnerability before following the process
in [`SECURITY.md`](../SECURITY.md). If a finding could affect confidentiality,
integrity, availability, secret-key material, signature/KEM acceptance, or safe
handling of hybrid keys, treat it as security-sensitive until maintainers say
otherwise. Note that [`SECURITY.md`](../SECURITY.md) asks reporters to first
consider whether an issue is serious enough to warrant a CVE; many valid findings
are best handled by a public issue and/or a fix PR.

**Dependencies are out of scope here.** Per [`SECURITY.md`](../SECURITY.md), weak
or broken cryptographic algorithm *implementations* provided by
[liboqs](https://github.com/open-quantum-safe/liboqs) or by OpenSSL's `libcrypto`
are not vulnerabilities in this project and must be reported to those projects
instead. A finding is in scope only when the defect is in the provider's own
logic — how it parses, composes, validates, allocates, frees, or dispatches —
including calling a `liboqs` or `libcrypto` API incorrectly in a way the upstream
cannot defend against.

## AI Disclosure

Reports and patches that use generative AI must say so, as required by
[`CONTRIBUTING.md`](../CONTRIBUTING.md). You are responsible for verifying
AI-generated code, tests, and prose before submitting them. Unverified,
AI-generated "vulnerability" reports that do not build and run against a real
provider entry point create disproportionate maintainer load and may lead to
restricted access to the Security Advisory interface (see
[`SECURITY.md`](../SECURITY.md)).

## Research Priorities

The project exists to serve **novel, experimental, and community** post-quantum
algorithms. Standardized algorithms (ML-KEM, ML-DSA, SLH-DSA, and similar) are
already well supported by OpenSSL itself and elsewhere and are candidates for
removal to shrink the maintenance and vulnerability surface (see
[issue #821](https://github.com/open-quantum-safe/oqs-provider/issues/821)).
Prioritize accordingly:

- **Experimental / community algorithms** and their provider-side handling: they
  are less exercised elsewhere and are the reason this project exists. Findings
  only in a standardized algorithm's handling are lower priority — that code may
  be removed rather than patched, and the algorithm is better maintained upstream.
- **Generic, algorithm-independent provider logic** (highest value, because one
  defect affects many algorithms at once):
  - **Decoders / parsers** —
    [`oqsprov/oqs_decode_der2key.c`](../oqsprov/oqs_decode_der2key.c) and the
    key-loading functions in
    [`oqsprov/oqsprov_keys.c`](../oqsprov/oqsprov_keys.c) — which turn
    attacker-supplied X.509 / PKCS#8 / PEM / DER bytes into key objects.
  - **Hybrid composition** — the length-prefixed concatenation of a traditional
    and a post-quantum component (defined in
    [`oqsprov/oqs_prov.h`](../oqsprov/oqs_prov.h) and split/joined in
    [`oqsprov/oqsprov_keys.c`](../oqsprov/oqsprov_keys.c)). The 4-byte
    classical-length prefix and the overall buffer length are attacker-controlled
    at the parse boundary.
  - **Key-management lifecycle** in
    [`oqsprov/oqsprov_keys.c`](../oqsprov/oqsprov_keys.c): allocation, reference
    counting, duplication/loading, and free/cleanup paths.
  - **Encoders** —
    [`oqsprov/oqs_encode_key2any.c`](../oqsprov/oqs_encode_key2any.c) and
    [`oqsprov/oqs_endecoder_common.c`](../oqsprov/oqs_endecoder_common.c).
  - **Signature, KEM, and hybrid-KEM dispatch** —
    [`oqsprov/oqs_sig.c`](../oqsprov/oqs_sig.c),
    [`oqsprov/oqs_kem.c`](../oqsprov/oqs_kem.c),
    [`oqsprov/oqs_hyb_kem.c`](../oqsprov/oqs_hyb_kem.c): buffer sizing when
    calling `liboqs`, return-value handling, and correct accept/reject semantics.
  - **Provider wiring** — [`oqsprov/oqsprov.c`](../oqsprov/oqsprov.c) and
    [`oqsprov/oqsprov_capabilities.c`](../oqsprov/oqsprov_capabilities.c):
    correct TLS group / signature-algorithm registration and `OSSL_PARAM`
    validation, so a hybrid never silently degrades to a single component.
- Tests and sanitizer coverage for any of the above.

## Provider API Preconditions

`oqsprovider` is invoked by OpenSSL's `libcrypto` (version 3.0 or later, including
4.x) through the provider dispatch tables. The *caller* (`libcrypto`) is trusted
to honour the provider ABI: correct argument types, honouring returned lengths,
and correct object lifetimes. Treat a report that requires `libcrypto` or the
application to violate that contract as out of scope.

Within that contract, the *data* is untrusted: bytes inside a decoded key,
certificate, signature, or ciphertext, and any embedded length, count, OID, or
`OSSL_PARAM` value ultimately originate from an attacker. `oqsprovider` must not
read past a supplied length, trust an embedded length prefix (especially the
hybrid classical-length field), or accept malformed / cross-parameter encodings.
Honour the OpenSSL convention that a `NULL` output buffer is a size query.

For secret-lifetime claims, trace secret-derived bytes across the intended
cleanup boundary (key free or an error path) and show an observation or reuse
path. A missing cleanse call by itself is a hardening lead, not a confirmed
vulnerability.

## Required Finding Workflow

1. Read [`.github/THREAT_MODEL.md`](THREAT_MODEL.md) and write down the boundary
   crossed.
2. Confirm the defect is in `oqsprovider`, not in `liboqs` or `libcrypto`.
3. Check [`SECURITY.md`](../SECURITY.md), existing issues/PRs, and the
   [`test/`](../test) directory for known behavior.
4. Identify the affected provider entry point, algorithm, parameter set, source
   location, OpenSSL version, and build options.
5. State which bytes / lengths remain attacker-controlled and, for hybrids, how
   the classical-length prefix relates to the actual buffer.
6. Build the affected configuration from a clean worktree (see below).
7. Create a minimal PoC or regression test that reaches the issue through a
   provider entry point (via the OpenSSL API or an existing test binary) and
   fails on the vulnerable build.
8. Run it under AddressSanitizer (the primary detector for this project) or with
   a wrong verify/decapsulation/KAT/interop result as evidence.
9. Confirm the impact against the threat model. Do not report out-of-scope or
   dependency behavior as an `oqsprovider` vulnerability.
10. Minimize the reproducer; document exact commands and expected vulnerable vs.
    fixed output. If proposing a patch, add a regression test that fails before
    and passes after.

A report without a build, a runnable reproducer through the provider, or a clear
threat-model mapping should be treated as a draft note, not a confirmed
vulnerability.

## Build Prerequisites

Verify the local toolchain instead of assuming it is suitable:

```sh
cmake --version
ninja --version   # or: make --version
cc --version
openssl version   # must be OpenSSL 3.0 or later (including 4.x)
```

`oqsprovider` requires an **OpenSSL 3.0-or-later** installation (the 4.x series is
supported) and a [liboqs](https://github.com/open-quantum-safe/liboqs)
installation. The convenience script
[`scripts/fullbuild.sh`](../scripts/fullbuild.sh) will build OpenSSL, `liboqs`,
and the provider together; the environment variables it honours are documented in
[`CONFIGURE.md`](../CONFIGURE.md) (for example `OPENSSL_BRANCH`, `LIBOQS_BRANCH`,
`liboqs_DIR`, `OPENSSL_INSTALL`). For a focused, reproducible security build,
prefer building the provider explicitly against known OpenSSL and `liboqs` trees.

For long-running builds, write full output to a log and keep only the tail and
final summary in the report:

```sh
log="$(mktemp "${TMPDIR:-/tmp}/oqsprov-build.XXXXXX.log")"
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug >"$log" 2>&1
rc=$?; tail -200 "$log"; echo "full log: $log"; exit "$rc"
```

## Standard Builds

Debug build (enables extra warnings and debug env vars such as `OQSPROV`,
`OQSDEC`, `OQSKEM`, `OQSSIG` for tracing):

```sh
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug \
  -DOPENSSL_ROOT_DIR=/path/to/openssl/install \
  -Dliboqs_DIR=/path/to/liboqs/install/lib/cmake/liboqs
cmake --build build
```

If the finding involves the KEM encoder/decoder paths, add
[`-DOQS_KEM_ENCODERS=ON`](../CONFIGURE.md#oqs_kem_encoders) and say so in the
report (it is OFF by default and uses random OIDs). Note
[`NOPUBKEY_IN_PRIVKEY`](../CONFIGURE.md#nopubkey_in_privkey) similarly changes
private-key serialization.

## AddressSanitizer Build

This mirrors the CI "Security checks" job (see
[`.github/workflows/linux.yml`](workflows/linux.yml)) and is the recommended way
to demonstrate memory-safety findings. Build OpenSSL (`enable-asan --debug`),
`liboqs`, and the provider all with ASan, then:

```sh
export ASAN_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DOPENSSL_ROOT_DIR=/path/to/asan/openssl/install \
  -Dliboqs_DIR=/path/to/asan/liboqs/install/lib/cmake/liboqs \
  -DCMAKE_C_FLAGS="$ASAN_C_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$ASAN_C_FLAGS"
cmake --build build
ASAN_OPTIONS="detect_stack_use_after_return=1,detect_leaks=1" \
  ctest --test-dir build --output-on-failure
```

For a standalone PoC, load the ASan-built `oqsprovider` into an ASan-built
OpenSSL (`openssl -provider oqsprovider ...`, or via `OSSL_PROVIDER_load` in a
small C program) and keep the PoC small, deterministic, and focused on one bug.

## Running Tests

Run the full suite after broad changes:

```sh
ctest --test-dir build --output-on-failure
```

Focused test binaries under `build/test/` map to areas of interest:

```sh
build/test/oqs_test_endecode        # encoders/decoders, key parsing
build/test/oqs_test_signatures      # signature + hybrid signature
build/test/oqs_test_kems            # KEM + hybrid KEM
build/test/oqs_test_groups          # TLS group registration
build/test/oqs_test_tlssig          # TLS signature negotiation
build/test/oqs_test_evp_pkey_params # EVP_PKEY parameter handling
build/test/oqs_test_alloc_failures  # allocation-failure / cleanup paths
```

Most take an algorithm name and paths to the test config and certs (see
[`test/CMakeLists.txt`](../test/CMakeLists.txt) for exact invocation). Shell
interop scripts under [`scripts/`](../scripts) (`oqsprovider-certgen.sh`,
`-certverify.sh`, `-cmssign.sh`, `-cmsverify.sh`, `-ca.sh`, `-pkcs12gen.sh`) and
[`scripts/test_tls_full.py`](../scripts/test_tls_full.py) exercise real
X.509/CMS/TLS flows and are good for end-to-end reproducers.

Do not submit a patch that changes key/signature encodings or algorithm
identifiers without confirming the endecode and interop tests still pass.

## Side Channels

Constant-time behavior of the KEM and signature math is the responsibility of
[liboqs](https://github.com/open-quantum-safe/liboqs) and `libcrypto`, not this
provider — report primitive timing issues upstream. A provider-level
side-channel report is in scope only if it traces secret data to a branch or
memory access **in `oqsprovider`'s own code** (for example, secret-dependent
handling while splitting or cleansing a hybrid private key). State which operands
are secret, which are public, and which are transcript-visible.

## Patch Expectations

Keep changes narrow and reviewable.

- Prefer validation at the parse/compose boundary that fixes every affected
  algorithm consistently over algorithm-specific special cases.
- Add a regression test that fails before the fix and passes after it.
- Run [`./scripts/format_code.sh`](../scripts/format_code.sh) before submitting
  (the project uses the LLVM / clang-format style; see
  [`CONTRIBUTING.md`](../CONTRIBUTING.md)).
- If your change touches generated code, regenerate via
  [`oqs-template/generate.py`](../oqs-template/generate.py) and include all files
  it changes (see [`CONFIGURE.md`](../CONFIGURE.md#pre-build-configuration));
  update [`CODEOWNERS`](CODEOWNERS) if relevant.
- Update documentation when behavior, build options, algorithm lists, or
  supported standards change.
- Documentation-only commits should carry `[skip ci]` (see
  [`CONTRIBUTING.md`](../CONTRIBUTING.md#resource-efficiency)).

## Report Template For Agents

```md
# Title

## Summary
One or two paragraphs: the bug and why it matters for oqsprovider.

## Threat Model Fit
- Boundary crossed (decode/parse, hybrid composition, dispatch, liboqs call,
  libcrypto call):
- Why the defect is in oqsprovider and not in liboqs/libcrypto/the caller:
- Attacker capability and input (cert, key file, signature, ciphertext, TLS
  message, OSSL_PARAM):
- In-scope rationale / out-of-scope considerations:

## Affected Target
- Repository commit and branch:
- OpenSSL version (>= 3.0, incl. 4.x), liboqs version/branch, compiler,
  sanitizer, OS:
- Build options (default? OQS_KEM_ENCODERS / NOPUBKEY_IN_PRIVKEY / static?):
- Provider entry point and source location:
- Algorithm and parameter set (experimental/community or standardized?):

## Impact
Concrete impact without exaggeration. For secret-lifetime findings: secret
source, intended cleanup boundary, residual bytes, observation/reuse path.

## Reproduction
Build and run commands from a clean checkout.

## Expected Output
Vulnerable output and fixed output (e.g. ASan trace before, clean after).

## PoC Or Regression Test
Minimal source, OpenSSL command line, or path to a test file.

## Recommended Fix
Patch direction and regression coverage.
```

If you cannot fill in these fields, keep investigating before submitting.
