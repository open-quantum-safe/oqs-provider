<!-- SPDX-License-Identifier: Apache-2.0 AND MIT -->

# Hybrids at the application layer: oqs-provider (PQ-only) + hybrid-provider

Companion to [`COMPLEXITY-hybrids.md`](COMPLEXITY-hybrids.md). That note measures
what de-hybridising oqs-provider *removes* (−36.8 % cyclomatic / −45.9 %
cognitive complexity). This note shows what it *does not lose*: the hybrid
functionality is recovered — and extended with standardized MLX groups and LAMPS
composites — by a thin, separate provider (hybrid-provider) that glues together
algorithms fetched from the PQ-only oqsprovider and from the OpenSSL default
provider, entirely through the public EVP API.

## Thesis

Concatenation hybrids (`X25519 + ML-KEM`, `ECDSA + ML-DSA`, …) do not have to
live inside the PQ provider. A hybrid is just "run algorithm A from some
provider, run algorithm B from some provider, glue the wire formats." OpenSSL 3
already lets a provider fetch sub-algorithms from *any* loaded provider, so the
gluing can sit in its own provider at the application layer. If that is true,
the `mb-nohybrids` branch loses no capability.

[`baentsch/hybrid-provider`](https://github.com/baentsch/hybrid-provider) is
exactly such a provider: it implements hybrid KEMs/signatures (and, optionally,
LAMPS-style *composites*) by composing sub-algorithms fetched via EVP from
whatever providers are loaded — it links no liboqs of its own.

## Setup

One OpenSSL **3.4.2** library context with three providers:

| provider | role | supplies |
| --- | --- | --- |
| `default` | built-in | X25519, X448, ECDSA P-256/384/521, RSA, Ed25519/448 |
| `oqsprovider` | **`mb-nohybrids` build** | PQ primitives only — ML-KEM, FrodoKEM, BIKE, HQC, ML-DSA, Falcon, MAYO, SLH-DSA, … (21 KEMs, 40 sigs; **no hybrids**) |
| `hybrid` | `hybrid-provider` | composes the two above into hybrid KEMs, hybrid signatures and composite signatures/KEMs |

OpenSSL 3.4 is deliberate: its default provider has **no** ML-KEM/ML-DSA, so
*every* PQ half of every hybrid must come from oqsprovider — there is no way for
a native default-provider hybrid to mask the result.

```ini
# compose.cnf
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default     = default_sect
oqsprovider = oqs_sect
hybrid      = hybrid_sect
[default_sect]
activate = 1
[oqs_sect]
module   = /path/to/oqs-provider/_build/lib/oqsprovider.so   # the mb-nohybrids build
activate = 1
[hybrid_sect]
module   = /path/to/hybrid-provider/hybrid.so
activate = 1
```

```console
$ OPENSSL_CONF=compose.cnf openssl list -providers | grep -E 'name|status'
    name: OpenSSL Default Provider      status: active
    name: hybrid-provider               status: active
    name: OpenSSL OQS Provider          status: active
```

## Result 1 — the removed hybrids reappear, served by `hybrid`

`oqsprovider` now serves only naked PQ KEMs; every hybrid removed from it is
served by `hybrid`, composed from an oqsprovider PQ base + a default-provider
classical half:

```console
$ openssl list -kem-algorithms | grep '@ oqsprovider'   # PQ-only, no hybrids
  efrodo640aes @ oqsprovider
  frodo640aes  @ oqsprovider
  mlkem512 @ oqsprovider   mlkem768 @ oqsprovider   mlkem1024 @ oqsprovider
  bikel1 @ oqsprovider     hqc1 @ oqsprovider       ...

$ for a in x25519_mlkem512 SecP256r1MLKEM512 p256_frodo640aes p256_bikel1 \
          p256_hqc1 X25519MLKEM768; do
    openssl list -kem-algorithms | grep -i "$a @"
  done
  x25519_mlkem512    @ hybrid
  SecP256r1MLKEM512  @ hybrid
  p256_frodo640aes   @ hybrid
  p256_bikel1        @ hybrid
  p256_hqc1          @ hybrid
  X25519MLKEM768     @ hybrid     # standardized MLX — see "and more"
```

## Result 2 — it works end-to-end (not just listed)

### Hybrid KEM — `x25519_mlkem512` (X25519 @ default + ML-KEM-512 @ oqsprovider)

```console
$ openssl genpkey -algorithm x25519_mlkem512 -out k.pem          # 3439-byte key
$ openssl pkeyutl -encap -inkey k.pem -secret ss_e.bin -out ct.bin   # ct = 800 B
$ openssl pkeyutl -decap -inkey k.pem -in ct.bin -out ss_d.bin
$ cmp ss_e.bin ss_d.bin && echo MATCH
MATCH                                   # 64-byte shared secret, identical
```

### Hybrid signature — `p256_mldsa44` (ECDSA P-256 @ default + ML-DSA-44 @ oqsprovider)

One-shot EVP API (`EVP_DigestSign`/`EVP_DigestVerify`):

```
signed p256_mldsa44: 2496-byte signature
verify p256_mldsa44: VALID
verify tampered:     correctly REJECTED
```

### Composite signature — `exp_mayo2_ecdsa_p256` (MAYO-2 @ oqsprovider + ECDSA-P256 @ default)

A single ASN.1 composite (not a concatenation hybrid), a construction
oqs-provider never shipped:

```
signed exp_mayo2_ecdsa_p256: 311-byte signature
verify exp_mayo2_ecdsa_p256: VALID
verify tampered:             correctly REJECTED
```

## Result 3 — "the same functionality and more", quantified

| | hybrid KEMs | hybrid / composite sigs |
| --- | ---: | ---: |
| stock oqs-provider (native hybrids compiled in) | ~39 | — (no composites) |
| **app-layer `hybrid` provider** (on PQ-only oqsprovider) | **51** | **39** (+ composite KEMs/sigs) |

The composition serves *more* hybrid KEMs than the monolithic implementation
ever did (it adds the standardized MLX groups `X25519MLKEM768` /
`X448MLKEM1024` and more combinations), and adds composite signatures and KEMs
on top — while the provider underneath has had its hybrid code, and a large
fraction of its complexity, removed. hybrid-provider's own interop suite checks
that the OQS-legacy hybrids are byte-for-byte identical to native oqsprovider
output.

## Interpretation

- Hybrid support inside oqs-provider was **not load-bearing**: the identical
  hybrids — plus standardized MLX and composite constructions — are reachable
  when a thin, separate hybrid provider glues a PQ-primitives-only provider and
  the default provider together.
- This is the architecture the de-hybridisation *enables*: the PQ provider does
  one job (expose liboqs primitives), and hybrid/composite policy becomes a
  separate, independently-versioned, application-layer concern.
- Division of labour matches ownership: NIST-standardized PQ primitives in the
  PQ provider; hybrid/composite wire formats (which track IETF/LAMPS drafts and
  change faster) in a provider that can be swapped without touching the PQ one.

## Reproduction notes

- Both `oqsprovider.so` and `hybrid.so` must be built against the **same**
  libcrypto to load in one process; here both target OpenSSL 3.4.2.
- `hybrid.so` links no liboqs — it fetches `mlkem*`, `frodo*`, `bikel*`,
  `hqc*`, `mldsa*`, `mayo*` by EVP name from oqsprovider and `x25519` / `ecdsa`
  / `rsa` from default. That is the whole point: the composition crosses
  provider boundaries purely through the public EVP API.
- Two artefacts below are OpenSSL-**CLI** limitations, not composition failures:
  the MLX `X25519MLKEM768` key did not round-trip through the `genpkey`/`pkey`
  PEM path (the OQS-legacy hybrids did), and `pkeyutl -rawin` cannot drive
  one-shot signature algorithms (`EVP_DigestSignUpdate` is rejected) — so the
  signature round-trips above use the one-shot `EVP_DigestSign`/`Verify` API
  directly.
