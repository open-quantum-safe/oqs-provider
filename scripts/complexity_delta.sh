#!/usr/bin/env bash
#
# complexity_delta.sh - Compare code-complexity of the current checkout against
# a base git ref, over the provider C sources (oqsprov/ and test/).
#
# Metrics (per function, summed over all functions in oqsprov/ and test/):
#   * Cyclomatic complexity : sum of lizard's CCN (McCabe number)
#   * Semantic size         : sum of lizard's token count (lexical/semantic
#                             token volume - a size proxy for "how much code
#                             the reader/compiler must reason about")
#   * NLOC                   : non-comment lines of code inside functions
#   * Functions              : number of analysed functions
#
# Requires: lizard (pip install lizard), git, python3.
#
# Usage:
#   scripts/complexity_delta.sh [--no-resolve-nopubkey] [BASE_REF] [PATH ...]
# Examples:
#   scripts/complexity_delta.sh                 # compare working tree vs main
#   scripts/complexity_delta.sh v0.9.0          # compare vs a tag
#   scripts/complexity_delta.sh main oqsprov    # only oqsprov/
#
# NOPUBKEY_IN_PRIVKEY resolution (ON by default):
#   lizard counts braces lexically and does not run the C preprocessor. The
#   asymmetric `#ifdef NOPUBKEY_IN_PRIVKEY` / `#else` inside oqsx_key_op
#   (oqsprov/oqsprov_keys.c) leaves lizard's brace depth out of sync, so it
#   STOPS discovering functions at that point and never analyses the lower half
#   of the file (oqsx_key_op, oqsx_key_new, oqsx_key_gen, ...). Any change to
#   those functions is then invisible to the metric. To avoid under-counting,
#   this script preprocesses the analysed sources by default, resolving
#   NOPUBKEY_IN_PRIVKEY to its *undefined* arm (the default build: the CMake
#   option defaults OFF) so braces balance and lizard sees the whole file. Both
#   refs are resolved identically; other preprocessor conditionals are left
#   untouched. Pass --no-resolve-nopubkey to measure the raw (un-preprocessed)
#   sources instead. --resolve-nopubkey is still accepted (now redundant).
#
set -euo pipefail

RESOLVE=1
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --resolve-nopubkey)    RESOLVE=1; shift;;
    --no-resolve-nopubkey) RESOLVE=0; shift;;
    *) echo "error: unknown option '$1'" >&2; exit 1;;
  esac
done

BASE_REF="${1:-main}"
shift || true
if (( $# )); then PATHS=("$@"); else PATHS=(oqsprov test); fi

command -v lizard >/dev/null 2>&1 || { echo "error: 'lizard' not found (pip install lizard)" >&2; exit 1; }
if (( RESOLVE )); then
  command -v python3 >/dev/null 2>&1 || { echo "error: 'python3' needed for --resolve-nopubkey" >&2; exit 1; }
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

TMPDIRS=()
WT="$(mktemp -d)"; TMPDIRS+=("$WT")
cleanup () {
  git worktree remove --force "$WT" >/dev/null 2>&1 || true
  for d in "${TMPDIRS[@]}"; do rm -rf "$d"; done
}
trap cleanup EXIT

# Preprocessor that resolves NOPUBKEY_IN_PRIVKEY as undefined, passing every
# other line (including all other directives) through verbatim.
RESOLVER="$(mktemp)"; TMPDIRS+=("$RESOLVER")
cat > "$RESOLVER" <<'PY'
import sys
M = "NOPUBKEY_IN_PRIVKEY"
stack = []  # ['nopub', emit_bool] for our macro; ['other'] for anything else
def suppressed():
    return any(e[0] == 'nopub' and not e[1] for e in stack)
for line in sys.stdin:
    s = line.strip()
    if s.startswith('#ifdef') or s.startswith('#ifndef') or s.startswith('#if'):
        if s == '#ifdef ' + M:   stack.append(['nopub', False]); continue  # undefined
        if s == '#ifndef ' + M:  stack.append(['nopub', True]);  continue  # undefined
        stack.append(['other'])
        if not suppressed(): sys.stdout.write(line)
        continue
    if s.startswith('#else'):
        if stack and stack[-1][0] == 'nopub': stack[-1][1] = not stack[-1][1]; continue
        if not suppressed(): sys.stdout.write(line)
        continue
    if s.startswith('#endif'):
        if stack and stack[-1][0] == 'nopub': stack.pop(); continue
        if stack: stack.pop()
        if not suppressed(): sys.stdout.write(line)
        continue
    if not suppressed(): sys.stdout.write(line)
PY

# Echo the paths lizard should analyse for a given set of inputs. With RESOLVE,
# build a throwaway mirror of the .c/.h files with the macro resolved.
prep_paths () {
  if (( ! RESOLVE )); then printf '%s\n' "$@"; return; fi
  local dest; dest="$(mktemp -d)"; TMPDIRS+=("$dest")
  local p f rel tgt out=()
  for p in "$@"; do
    if [[ -d "$p" ]]; then
      while IFS= read -r f; do
        rel="${f#"$p"/}"; tgt="$dest/$(basename "$p")/$rel"
        mkdir -p "$(dirname "$tgt")"
        python3 "$RESOLVER" < "$f" > "$tgt"
      done < <(find "$p" -type f \( -name '*.c' -o -name '*.h' \))
      out+=("$dest/$(basename "$p")")
    elif [[ -f "$p" ]]; then
      tgt="$dest/$(basename "$p")"; python3 "$RESOLVER" < "$p" > "$tgt"; out+=("$tgt")
    fi
  done
  printf '%s\n' "${out[@]}"
}

# Sum lizard CSV columns: 1=nloc 2=ccn 3=token (one row per function).
sum_metrics () {
  lizard "$@" --csv 2>/dev/null | awk -F, '
    { nloc += $1; ccn += $2; tok += $3; fn += 1 }
    END { printf "%d %d %d %d\n", fn, ccn, nloc, tok }'
}

# Analyse the base ref in a throwaway worktree so untracked files / local
# changes in the main checkout do not affect the numbers.
git worktree add -q --detach "$WT" "$BASE_REF"

base_paths=(); for p in "${PATHS[@]}"; do base_paths+=("$WT/$p"); done

mapfile -t base_analyse < <(prep_paths "${base_paths[@]}")
mapfile -t head_analyse < <(prep_paths "${PATHS[@]}")

read -r b_fn b_ccn b_nloc b_tok < <(sum_metrics "${base_analyse[@]}")  # base
read -r h_fn h_ccn h_nloc h_tok < <(sum_metrics "${head_analyse[@]}")  # current

row () { # label base head
  local pct="n/a"
  (( $2 != 0 )) && pct="$(awk -v a="$2" -v b="$3" 'BEGIN{printf "%+.1f%%", (b-a)*100.0/a}')"
  printf "%-28s %10s %12s %10d %10s\n" "$1" "$2" "$3" "$(( $3 - $2 ))" "$pct"
}

echo "Base ref        : $BASE_REF ($(git rev-parse --short "$BASE_REF"))"
echo "Current checkout: $(git rev-parse --short HEAD) (+ working tree)"
echo "Paths           : ${PATHS[*]}"
echo "Resolve NOPUBKEY : $(( RESOLVE ))"
echo
printf "%-28s %10s %12s %10s %10s\n" "metric" "base" "current" "delta" "delta%"
printf -- "---------------------------------------------------------------------------\n"
row "functions"               "$b_fn"   "$h_fn"
row "cyclomatic (sum CCN)"    "$b_ccn"  "$h_ccn"
row "nloc (in-function)"      "$b_nloc" "$h_nloc"
row "semantic size (tokens)"  "$b_tok"  "$h_tok"
