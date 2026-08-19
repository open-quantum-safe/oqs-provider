# CygnetLib Drop-In Remediation Plan

Target repo: `sanctumsecopsmssp/oqs-provider` (fork of `open-quantum-safe/oqs-provider`, created 2026-08-19)
Rename to: `sanctumsecopsmssp/cygnet-provider`
Owning repo for policy/evidence: `sanctumsecopsmssp/CygnetLib`
Tracking issue: `sanctumsecopsmssp/CygnetLib#4`

## Goal

Convert CygnetLib from a typed interface specification with stub PQC implementations into a
drop-in provider consumable by any application linking libcrypto, without reimplementing
lattice or hash-based primitives in Python.

Architecture after remediation:

```
application (unmodified)
    -> libcrypto EVP high-level API
        -> cygnet-provider.so   [policy gate + composite OIDs + evidence self-test]
            -> liboqs / OpenSSL FIPS provider   [actual primitives]

CygnetLib (Python)  -> ctypes binding to cygnet-provider.so  [tooling, audit, evidence]
```

## Remediation Items

### R1 — Rename fork and wire upstream remote
- Rename repo to `cygnet-provider` in Settings (no API tool available for rename; manual).
- Enable Issues on the fork; they are disabled by default and blocked ticket creation here.
- `git remote add upstream https://github.com/open-quantum-safe/oqs-provider.git`
- Add a quarterly scheduled workflow that opens a PR merging `upstream/main`.
- Keep `LICENSE.txt` (upstream MIT) alongside a new `NOTICE` attributing Sanctum additions.
- Status: pending

### R2 — Strip non-CNSA-2.0 algorithm families
- Edit `oqs-template/generate.yml` to emit only ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768.
- Regenerate `oqsprov_capabilities.c`, `oqsencoders.inc`, `oqsdecoders.inc`.
- Record every removed family in `docs/removed-algorithms.md`; a smaller surface is a
  cheaper CMVP and audit conversation.
- Do not remove the encoder/decoder machinery itself — see R6.
- Status: pending

### R3 — Composite keymgmt and signature for the Sanctum PEN arc
- Arc: `1.3.6.1.4.1.65953`
- `CYGNET-L5-Triple` = ML-KEM-1024 (confidentiality) + SLH-DSA-SHA2-256s + ML-DSA-87
  (two independent signature families for defense in depth).
- `ALBIREO` = second composite profile.
- Implement as `OSSL_OP_KEYMGMT` + `OSSL_OP_SIGNATURE` following the component-OID-list
  structure in `draft-ietf-lamps-pq-composite-sigs`, which the CygnetLib evidence file
  `ietf-pqc-interop.json` already claims alignment with.
- This is the only genuinely novel code in the fork. Everything else is integration.
- Status: pending

### R4 — Fail-closed policy gate in provider init
- Port the rules in `cygnet/policy.py` into `oqsprov/cygnet_prov_init.c`.
- Deny by default: an algorithm absent from the allowlist is not exposed, not warned about.
- Refuse to load if CNSA 2.0 required-set coverage regresses below 6/6.
- `CYGNET_POLICY_RELAX=1` escape hatch for lab work only; assert it is unset in CI.
- Emit `actv-results.json` and `cnsa2-compliance-matrix.json` at load time rather than
  build time, so posture is proven per host.
- Status: skeleton committed on `cygnet/policy-gate`; not yet wired into CMakeLists.txt.

### R5 — Repoint CygnetLib FFI and delete the stubs
- `cygnet/ffi/bindings.py`: make `LibOQSProvider` / `OpenSSLProvider` bind the built
  `cygnet-provider.so` instead of returning interface stubs.
- Delete the stub round-trip shims in `cygnet/kem/kem.py` and the parallel files under
  `cygnet/sig/`, `cygnet/composite/`.
- Update `evidence/actv-results.json` generation so the note about
  "interface-specification stubs" can be removed truthfully.
- Uncomment `pyoqs` / `cryptography` in `requirements.txt` and lock them.
- Status: pending

### R6 — SSH and PKCS#8 key formats (separate track)
The fork already ships `oqs_encode_key2any.c` and `oqs_decode_der2key.c`, giving
SubjectPublicKeyInfo / PKCS#8 / PEM round-tripping for the PQC key types. This closes
most of the CygnetLib `pki` gap for free.

It does **not** close the OpenSSH gap. OpenSSH does not consume OpenSSL providers for its
key types, so the original SSH key problem still needs either:
- an OpenSSH wire-format writer (length-prefixed blobs) in CygnetLib's `pki` module, or
- routing through `ssh-agent` / a PKCS#11 or `sk-` middleware path.

Do not conflate this with the provider work. Provider gets ecosystem reach; encoders get a
key that can be pasted into `authorized_keys`.

## Verification Gates

Every item ships with evidence, not narrative:

1. `openssl list -providers` shows `Cygnet Provider 0.1.0-dev`, status active.
2. `openssl list -kem-algorithms -provider cygnet` shows exactly the allowlist.
3. Negative test: an algorithm removed in R2 fails, and fails closed rather than silently
   falling through to the default provider.
4. `openssl req -provider cygnet -newkey mldsa87` produces a parseable cert.
5. Composite round-trip vectors from the Sanctum internal harness pass against R3.
6. `pytest` in CygnetLib passes with FFI bound to the real `.so`, no stub branches taken.

## openssl.cnf Activation

Keep the default provider active alongside Cygnet, or every algorithm the fork does not
implement disappears.

```ini
[provider_sect]
default = default_sect
cygnet  = cygnet_sect

[default_sect]
activate = 1

[cygnet_sect]
module   = /usr/lib/ossl-modules/cygnet-provider.so
activate = 1
```

## Known Constraint

For the NIST-standardized set alone, OpenSSL 3.5+ already ships ML-KEM, ML-DSA and SLH-DSA
natively. The fork's value is therefore *not* PQC availability. It is policy enforcement,
composite OIDs under the Sanctum arc, and machine-readable compliance evidence. Position it
that way internally and externally; claiming otherwise invites a comparison you lose.

FIPS status: OpenSSL cert #4985 covers 3.1.2; 3.5.4 is submitted and still in CMVP review.
Nobody has a validated PQC module in hand yet. Cygnet inherits whatever the loaded module
carries and should say so explicitly in client-facing documentation.
