#!/usr/bin/env bash
#
# cognitive_delta.sh - Compare *cognitive* complexity (SonarSource metric) of
# the current checkout against a base git ref, over the provider C sources
# (oqsprov/ and test/).
#
# Cognitive complexity differs from cyclomatic (McCabe) complexity: it adds a
# nesting penalty, counts a `switch` as +1 (not +1 per case) and collapses runs
# of the same boolean operator. It is therefore a better proxy for how hard the
# control flow is to *understand*, not just how many paths it has.
#
# It is computed by clang-tidy's `readability-function-cognitive-complexity`
# check (a faithful implementation of the SonarSource algorithm). Because
# clang-tidy must actually parse the translation units, a CMake compile
# database (compile_commands.json) is required for each tree; this script
# generates one via `cmake ... -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` (configure
# only, no build).
#
# Requires: clang-tidy (pip install clang-tidy), cmake, git, and a usable
#           liboqs (its *_DIR is auto-detected from an existing build cache or
#           taken from $LIBOQS_DIR).
#
# Usage:
#   scripts/cognitive_delta.sh [BASE_REF] [PATH ...]
# Examples:
#   scripts/cognitive_delta.sh                 # compare working tree vs main
#   scripts/cognitive_delta.sh HEAD~1          # compare working tree vs parent
#   scripts/cognitive_delta.sh main oqsprov    # only oqsprov/
#
# Environment:
#   LIBOQS_DIR   path to liboqs CMake package dir (…/lib/cmake/liboqs).
#                If unset it is read from <BUILD_DIR>/CMakeCache.txt.
#   BUILD_DIR    build dir to (re)use for the *current* tree (default: _build).
#
set -euo pipefail

BASE_REF="${1:-main}"
shift || true
if (( $# )); then PATHS=("$@"); else PATHS=(oqsprov); fi

command -v clang-tidy >/dev/null 2>&1 || {
  echo "error: 'clang-tidy' not found (pip install clang-tidy)" >&2; exit 1; }
command -v cmake >/dev/null 2>&1 || { echo "error: 'cmake' not found" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

BUILD_DIR="${BUILD_DIR:-_build}"

# Resolve liboqs_DIR: prefer $LIBOQS_DIR, else read it from the current build.
if [[ -z "${LIBOQS_DIR:-}" ]]; then
  if [[ -f "$BUILD_DIR/CMakeCache.txt" ]]; then
    LIBOQS_DIR="$(sed -n 's/^liboqs_DIR:PATH=//p' "$BUILD_DIR/CMakeCache.txt")"
  fi
fi
[[ -n "${LIBOQS_DIR:-}" ]] || {
  echo "error: liboqs_DIR unknown; set \$LIBOQS_DIR or create $BUILD_DIR first" >&2
  exit 1; }

CT_CHECK='-*,readability-function-cognitive-complexity'
CT_CFG='{CheckOptions: {readability-function-cognitive-complexity.Threshold: 0, readability-function-cognitive-complexity.DescribeBasicIncrements: false}}'

# Sum "has cognitive complexity of N" over every function in the given files.
# Echoes "<function_count> <cognitive_sum>".
cog_sum () {
  local db="$1"; shift
  clang-tidy -p "$db" --quiet --checks="$CT_CHECK" --config="$CT_CFG" "$@" 2>/dev/null \
    | grep -oE 'has cognitive complexity of [0-9]+' \
    | grep -oE '[0-9]+' \
    | awk '{ s += $1; n += 1 } END { printf "%d %d\n", n+0, s+0 }'
}

ensure_db () { # $1=source_dir  $2=build_dir
  if [[ ! -f "$2/compile_commands.json" ]]; then
    cmake -S "$1" -B "$2" -Dliboqs_DIR="$LIBOQS_DIR" \
          -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null 2>&1
  fi
}

# --- current checkout -------------------------------------------------------
ensure_db "$REPO_ROOT" "$BUILD_DIR"
cur_files=(); for p in "${PATHS[@]}"; do cur_files+=("$REPO_ROOT/$p"/*.c); done
read -r h_fn h_cog < <(cog_sum "$BUILD_DIR" "${cur_files[@]}")

# --- base ref in a throwaway worktree --------------------------------------
WT="$(mktemp -d)"
cleanup () { git worktree remove --force "$WT" >/dev/null 2>&1 || true; rm -rf "$WT"; }
trap cleanup EXIT
git worktree add -q --detach "$WT" "$BASE_REF"
ensure_db "$WT" "$WT/_cc"
base_files=(); for p in "${PATHS[@]}"; do base_files+=("$WT/$p"/*.c); done
read -r b_fn b_cog < <(cog_sum "$WT/_cc" "${base_files[@]}")

# --- report -----------------------------------------------------------------
row () { # label base head
  local pct="n/a"
  (( $2 != 0 )) && pct="$(awk -v a="$2" -v b="$3" 'BEGIN{printf "%+.1f%%", (b-a)*100.0/a}')"
  printf "%-28s %10s %12s %10d %10s\n" "$1" "$2" "$3" "$(( $3 - $2 ))" "$pct"
}

echo "Base ref        : $BASE_REF ($(git rev-parse --short "$BASE_REF"))"
echo "Current checkout: $(git rev-parse --short HEAD) (+ working tree)"
echo "Paths           : ${PATHS[*]} (C translation units only)"
echo "clang-tidy      : $(clang-tidy --version | sed -n 's/.*version \([0-9.]*\).*/\1/p' | head -1)"
echo
printf "%-28s %10s %12s %10s %10s\n" "metric" "base" "current" "delta" "delta%"
printf -- "---------------------------------------------------------------------------\n"
row "functions (with CC>0)"       "$b_fn"  "$h_fn"
row "cognitive complexity (sum)"  "$b_cog" "$h_cog"
