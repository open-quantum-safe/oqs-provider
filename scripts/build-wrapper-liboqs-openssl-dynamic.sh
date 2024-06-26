#!/bin/bash
# build-wrapper-liboqs-openssl-dynamic.sh, ABr
#
# Leverages fullbuild.sh to create a local dynalink oqs-provider which can
# be loaded into the openssl installed on the host.
#
# Usage:
#   ./scripts/build-wrapper-liboqs-openssl-dynamic.sh [target]
#     [target] - do_main: Only entry point to use ;)
#
# Requires the use of liboqs pulled and built using the analogous script:
#   [the_liboqs_dir]/scripts/build-wrapper-openssl-static.sh

# TODO: support building on non-macOS platforms

# top-level settings - modify in environment from default listed here
the_liboqs_dir="${the_liboqs_dir:-}"
the_oqs_algs_enabled="${the_oqs_algs_enabled:-STD}"

# supported dynalibs
if [[ "$OSTYPE" == "darwin"* ]]; then
  SHLIBEXT="dylib"
  STATLIBEXT="dylib"
else
  SHLIBEXT="so"
  STATLIBEXT="a"
fi

# locate script source directory
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
g_SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
the_top_dir="`realpath $g_SCRIPT_DIR/..`"

# set the liboqs directory if unset
[ x"$the_liboqs_dir" = x ] && the_liboqs_dir="`realpath "$the_top_dir"/../liboqs`"

# retrieve the liboqs version from the liboqs folder - must exist
the_liboqs_ver="`"$the_liboqs_dir"/scripts/build-wrapper-openssl-static.sh get_oqs_version`"
the_rc=$? ; [ $the_rc -ne 0 ] && echo "$the_liboqs_ver" && exit $the_rc

##############################################################
# PEP
function do_main {
  local l_rc=0

  # ensure liboqs is built for this platform; it is used for fullbuild.sh
  liboqs_DIR="$the_top_dir/.local"
  if [ ! -s "$liboqs_DIR"/lib/liboqs.a ] ; then
    echo "Build liboqs from '$the_liboqs_dir'..."
    cd "$the_liboqs_dir"
    cmake -GNinja \
      -DOQS_ALGS_ENABLED=$the_oqs_algs_enabled \
      -DCMAKE_INSTALL_PREFIX=$the_top_dir/.local \
      -S . -B _build
    l_rc=$? ; [ $l_rc -ne 0 ] && return $l_rc
    cd _build && ninja && ninja install
    l_rc=$? ; [ $l_rc -ne 0 ] && return $l_rc
  fi

  # leverage the existing fullbuild.sh
  export liboqs_DIR
  "$the_top_dir"/scripts/fullbuild.sh -f || return $?

  # report on provider location
  echo 'Dynalib:'
  find "$the_top_dir"/_build -type f -name '*.'$SHLIBEXT -exec ls -la {} \; | sed -e 's/^/  /'
  local l_oqs_provider_path="$(dirname "`find "$the_top_dir"/_build -type f -name '*.'$SHLIBEXT | head -n 1`")"
  local l_oqs_provider_name='oqsprovider'
  echo 'Algorithms:'
  openssl list -kem-algorithms -provider-path "$l_oqs_provider_path" -provider $l_oqs_provider_name | sed -e 's/^//'
  echo 'Signatures:'
  openssl list -signature-algorithms -provider-path "$l_oqs_provider_path" -provider $l_oqs_provider_name | sed -e 's/^//'
  echo 'Exports:'
  echo "  export OQS_PROVIDER_NAME='$l_oqs_provider_name'"
  echo "  export OQS_PROVIDER_PATH='$l_oqs_provider_path'"
  echo 'Example:'
  echo '  openssl list -kem-algorithms -provider-path "$OQS_PROVIDER_PATH" -provider $OQS_PROVIDER_NAME'
  echo '  openssl list -signature-algorithms -provider-path "$OQS_PROVIDER_PATH" -provider $OQS_PROVIDER_NAME'

  return 0
}

l_do_run=1
if [ "x$1" != "x" ]; then
  [ "x$1" = "xsource-only" ] && l_do_run=0
fi
if [ $l_do_run -eq 1 ]; then
  if [ x"$1" = x ] ; then
    l_func='do_main'
  else
    l_func="$1"
    shift
  fi
  [ x"$l_func" != x ] && eval "$l_func" "$@" || true
else
  true
fi

