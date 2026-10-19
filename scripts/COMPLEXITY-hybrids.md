<!-- SPDX-License-Identifier: Apache-2.0 AND MIT -->

# Code-complexity impact of removing hybrid algorithms

This note documents the complexity reduction obtained by moving all hybrid
(multi-component) algorithm logic out of oqs-provider, leaving a provider that
implements liboqs primitives only. It uses the measurement methodology
described in [`COMPLEXITY.md`](COMPLEXITY.md).

The measurement is taken on the `mb-nohybrids` branch, which is now a
**complete, compiling de-hybridisation** (earlier revisions of this note
described a non-compiling demonstrator; those interim figures were a lower
bound). The branch builds and links `oqsprovider.so`, passes the ctest
suite (9 passing, 1 conditionally skipped), and at runtime registers only pure-PQ
algorithms — no hybrid KEMs. `OQSX_KEY` is
collapsed to a single component, the hybrid rows are gone from `nid_names`,
TLS groups/code-points and the OID list, and the generator (`generate.yml`,
the Jinja fragments and `generate.py`) no longer describes or emits hybrids.

## Refs used

| | ref | note |
| --- | --- | --- |
| **before** | `main` | baseline |
| **after**  | `mb-nohybrids` | complete de-hybridisation (builds, links, tests pass) |

## Note: lizard needs the NOPUBKEY_IN_PRIVKEY macro resolved

`lizard`'s brace counter desyncs at the asymmetric
`#ifdef NOPUBKEY_IN_PRIVKEY` / `#else` inside `oqsx_key_op`, so left to itself it
stops finding functions partway through `oqsprov/oqsprov_keys.c` — on **any** ref.
The lower half of the file (`oqsx_key_op`, `oqsx_key_new`, `oqsx_key_gen`, …)
is then invisible to the cyclomatic metric, which is exactly where much of the
hybrid logic lives, so a raw run would **under-report** this change.

`NOPUBKEY_IN_PRIVKEY` defaults `OFF` (see `CMakeLists.txt`), so resolving that
one macro to its undefined arm restores balanced braces and lets lizard see the
whole file. `complexity_delta.sh` does this **by default** (pass
`--no-resolve-nopubkey` to measure the raw sources); the figures below rely on
it. The cognitive figures (clang-tidy) run the real preprocessor and need no
such workaround.

## Cyclomatic complexity + size (lizard, build-free)

```sh
$ scripts/complexity_delta.sh main oqsprov
```

| metric | main | mb-nohybrids | delta |
| --- | ---: | ---: | ---: |
| functions | 297 | 218 | **−26.6%** |
| cyclomatic (sum CCN) | 1335 | 844 | **−36.8%** |
| nloc (in-function) | 4805 | 2921 | **−39.2%** |
| semantic size (tokens) | 32823 | 19088 | **−41.8%** |

## Cognitive complexity (clang-tidy, SonarSource metric)

Cognitive complexity adds a nesting penalty, counts a `switch` as +1 (not +1
per case) and collapses runs of the same boolean operator — a better proxy for
how hard the control flow is to *understand*. It is computed by clang-tidy's
`readability-function-cognitive-complexity` check, which needs real translation
units (now available because the branch compiles).

```sh
$ scripts/cognitive_delta.sh main oqsprov
```

| metric | main | mb-nohybrids | delta |
| --- | ---: | ---: | ---: |
| functions (CC>0) | 756 | 452 | **−40.2%** |
| cognitive complexity (sum) | 2711 | 1468 | **−45.9%** |

As anticipated, the cognitive drop (**−45.9%**) exceeds the cyclomatic drop
(**−36.8%**): the removed hybrid code was `numkeys` loops and classical/PQ
branches nested inside keytype switches — precisely the nested control flow
that cognitive complexity penalises most.

### Where it is concentrated (`oqsprov/oqsprov_keys.c`, macro resolved)

| metric | main | mb-nohybrids | delta |
| --- | ---: | ---: | ---: |
| functions | 35 | 23 | −34.3% |
| cyclomatic (sum CCN) | 260 | 102 | **−60.8%** |
| nloc (in-function) | 1186 | 420 | −64.6% |
| tokens | 7865 | 2558 | −67.5% |

Raw file size: `oqsprov_keys.c` 1746 → 690 lines (−60%); whole `oqsprov/`
16537 → 9688 lines (−41%). `oqs_hyb_kem.c` (278 lines) is deleted outright.

The reduction splits into (i) self-contained hybrid-only functions removed
whole — `setECParams`, `oqsx_hybsig_init`, `oqshybkem_init_ec{p,bp,x}`,
`oqsx_comp_set_offsets`, `oqsx_comp_set_idx`, `oqsx_key_set_composites`,
`oqsx_key_recreate_classickey`, `oqsx_key_gen_evp_key_{sig,kem}`,
`oqsx_get_hybrid_params`, `oqsx_key_is_hybrid`, `get_reverseshare`, the
classical EC curve tables (`nids_sig/ecp/ecbp/ecx`), and `oqs_hyb_kem.c`; and
(ii) interleaved `numkeys>1` / `classical_pkey` branches collapsed to the
single-key path inside shared functions (`oqs_sig_{sign,verify}_directly`,
`oqsx_get_params`/`oqsx_set_params`, `oqsx_key_op`, `oqsx_key_new`,
`oqsx_key_gen`, `oqsx_from{data,_pkcs8}`, `oqsx_pki_priv_to_der`,
`oqsx_to_text`); and (iii) the whole hybrid data/registration surface — hybrid
rows in `nid_names`, hybrid groups/code-points and
`oqs_patch_codepoints`/OID-patching in `oqsprov_capabilities.c`/`oqsprov.c`,
and the hybrid KEM/keymgmt dispatch.

## Interpretation

- At **−36.8% cyclomatic / −45.9% cognitive** a full de-hybridisation roughly
  doubles the earlier non-compiling-demonstrator estimate (−18.4% cyclomatic):
  hybrids pervade the key model more than any one algorithm family does.
- `OQSX_KEY` collapsing to a single component is the structural centre of the
  win — every encode/decode/keymgmt/KEM/SIG path stops carrying the
  component-array + classical-EVP machinery, which is why `oqsprov_keys.c`
  alone loses ~61% of its cyclomatic complexity.
- Cognitive is the primary metric (it is what `COMPLEXITY.md` tracks); the
  lizard cyclomatic/size figures corroborate it build-free.

## Functionality is not lost

Removing the complexity above does not remove capability.
[`HYBRIDS-AT-APP-LAYER.md`](HYBRIDS-AT-APP-LAYER.md) shows a separate, thin
provider — [`baentsch/hybrid-provider`](https://github.com/baentsch/hybrid-provider)
— gluing the PQ-only oqsprovider and the OpenSSL default provider over the public
EVP API, recovering every removed hybrid (byte-for-byte) and adding standardized
MLX groups and composite signatures/KEMs — all at the application layer.
