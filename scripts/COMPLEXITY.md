<!-- SPDX-License-Identifier: Apache-2.0 AND MIT -->

# Measuring code complexity in oqs-provider

This note documents **how** the two complexity-delta scripts in this directory
work, so their output can be reproduced and checked. It describes the method
only; any concrete figures belong in the pull request that reports them.

The **primary** metric is **cognitive complexity** (SonarSource); cyclomatic
complexity and size are reported as cheap, build-free corroboration.

| Metric | Tool | Role |
| --- | --- | --- |
| **Cognitive complexity** (SonarSource, 2017) | `clang-tidy` check `readability-function-cognitive-complexity` | **primary** — how hard the control flow is to *understand*: adds a nesting penalty, counts `switch` as +1 (not per-case), collapses runs of the same boolean operator |
| Cyclomatic complexity (McCabe, 1976) | [`lizard`](https://github.com/terryyin/lizard) | corroborating — number of independent paths ≈ minimum branch-coverage test cases; also yields NLOC / token / function counts in the same run |

The two scripts live next to this file:

- `scripts/cognitive_delta.sh`   — cognitive complexity (clang-tidy / SonarSource)
- `scripts/complexity_delta.sh`  — cyclomatic complexity + size (lizard)

Both compare a **base git ref** (checked out into a throwaway `git worktree`, so
untracked/scratch files in the working copy do not skew the result) against the
**current checkout**.

## Prerequisites

```sh
pip install clang-tidy lizard     # clang-tidy >= 15 (used: 22.1.8), lizard >= 1.24
# cmake + a usable liboqs are needed only for cognitive_delta.sh, because
# clang-tidy must parse the translation units (it uses compile_commands.json,
# which the script generates with `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`).
```

`cognitive_delta.sh` auto-detects `liboqs_DIR` from `_build/CMakeCache.txt`
(override with `LIBOQS_DIR=…`). Keep the CMake options identical for both trees
so the same `#ifdef` branches are analysed.

## Usage

```sh
# cognitive complexity (primary), provider sources only, vs the merge base:
scripts/cognitive_delta.sh main oqsprov

# cyclomatic complexity + size (corroborating), build-free:
scripts/complexity_delta.sh main oqsprov
```

Each prints a `base → current` delta table (functions, cognitive/cyclomatic sum,
NLOC, tokens). Omit the path argument to include `test/` as well as `oqsprov/`.

To list the per-function cognitive scores behind a delta:

```sh
clang-tidy -p _build --quiet \
  --checks='-*,readability-function-cognitive-complexity' \
  --config='{CheckOptions: {readability-function-cognitive-complexity.Threshold: 0}}' \
  oqsprov/oqsprov.c 2>/dev/null | grep 'has cognitive complexity of'
```

Read cyclomatic complexity as a cross-check, not the headline: flat
`if (getenv(...))` ladders inflate the McCabe number while being mechanically
trivial, whereas cognitive complexity reflects real reading difficulty better.

> **lizard blind spot (handled by default).** lizard counts braces lexically
> without a preprocessor, so the asymmetric `#ifdef NOPUBKEY_IN_PRIVKEY` / `#else`
> inside `oqsx_key_op` desyncs its brace depth: it stops finding functions there
> and never analyses the lower half of `oqsprov/oqsprov_keys.c` (`oqsx_key_op`,
> `oqsx_key_new`, `oqsx_key_gen`, …), which would under-count any change to the
> key handler. `complexity_delta.sh` therefore preprocesses the analysed sources
> by default (`NOPUBKEY_IN_PRIVKEY` undefined = default build) so braces balance.
> Pass `--no-resolve-nopubkey` to measure the raw sources instead.

## Continuous integration

`.github/workflows/complexity.yml` runs both measures against the pull request's
merge base and writes the delta tables to the job summary. It is **advisory**:
both jobs use `continue-on-error`, so the workflow never gates a PR — it only
makes complexity trends visible. It can later be turned into a blocking ratchet
(a committed complexity budget, or a cap on the diff against the merge base) if
the project decides to; cyclomatic runs build-free (lizard only), while cognitive
reuses the CI build to emit `compile_commands.json`.

## Caveats

- **Tool/version sensitivity.** `clang-tidy`'s check follows the SonarSource spec
  but is not bit-identical to SonarQube's own (commercial for C/C++) analyzer;
  results depend on the active `#ifdef` configuration, so both trees must be
  configured identically.
- Cognitive and cyclomatic numbers are not comparable to each other; compare each
  metric only against itself across refs.
