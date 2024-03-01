#!/bin/bash
# build-wrapper-liboqs-openssl-static.sh, ABr
#
# Build support for static oqs-provider library for macOS / iOS / android.
# Specifically created for projects which want static library in order to build
# their own platform-specific dynalib containing a known specific version of
# openssl / liboqs / oqs-provider.
#
# *Requires* that liboqs is built one folder above with an expected 'build' output folder.
#
# Usage:
#   ./scripts/build-wrapper-liboqs-openssl-static.sh [target]
#     [target] - do_main: Build all, create export
#              - [function]: Any function such as build_apple_macosx
#
# On success, the generated [build/export] folder below can be used as
# input to the oqs-provider build.
#
# Output:
# ./build - output folder
# \-> android
#     \-> [archs] - one of arm64-v8a / armeabi-v7a / x86 / x86_64
#         \-> [output] - cmake output and build files
# \-> apple
#     \-> [device] - one of macOS / iphoneos / iphonesimulator
#         \-> lib - contains fat lib with all archs
#         \-> [archs] - one of arm64 / x86_64 architecture
#             \-> [output] - cmake output and build files
# \-> export - packaged output
#     \-> android
#         \-> [version] - version automatically determined from build output
#             \-> [archs] - one of arm64-v8a / armeabi-v7a / x86 / x86_64
#                 \-> lib - static library output
#     \-> apple
#         \-> [version] - version automatically determined from build output
#             \-> [device] - one of macOS / iphoneos / iphonesimulator
#                 \-> lib - contains fat lib with all archs
#
# Requires the use of liboqs pulled and built using the analogous script:
#   [the_liboqs_dir]/scripts/build-wrapper-openssl-static.sh

# top-level settings - modify in environment from defaults listed here
the_openssl_ver="${the_openssl_ver:-3.2.1}"
the_openssl_dir="${the_openssl_dir:-$HOME/proj/git/src/triplecyber.visualstudio.com/abruce-dev/Tc32/External/openssl}"
the_liboqs_dir="${the_liboqs_dir:-}"
the_ios_target="${the_ios_target:-17.0}"
the_android_api_level="${the_android_api_level:-34}"

# enable debug to get explicit compiler command lines
the_cmake_build_verbose_flag="${the_cmake_build_verbose_flag:-0}"
the_cmake_build_verbose_option=''
[ x"$the_cmake_build_verbose_flag" = x1 ] && the_cmake_build_verbose_option='--verbose'

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

# retrieve the liboqs version from the liboqs folder
the_liboqs_ver="`"$the_liboqs_dir"/scripts/build-wrapper-openssl-static.sh get_oqs_version`"
the_rc=$? ; [ $the_rc -ne 0 ] && echo "$the_liboqs_ver" && exit $the_rc

# assume the build directory
the_build_dir_name='build'
the_build_dir_path="$the_top_dir/$the_build_dir_name"

# assume the .CMake folder
the_cmake_dir_name='.CMake'
the_cmake_dir_path="$the_top_dir/$the_cmake_dir_name"

# the export folder is underneath build to be ignored by git
the_export_dir_name='export'
the_export_dir_path="$the_build_dir_path"/$the_export_dir_name

##############################################################
# APPLE build support

# perform a single apple cmake build
function build_apple_variant {
  local i_device="$1" ; shift
  local i_arch="$1" ; shift
  local i_platform="$1" ; shift

  # locals
  local l_rc=0
  local l_type='apple'
  local l_openssl_plat_dir="$the_openssl_dir/$l_type/$the_openssl_ver/$i_device"
  local l_liboqs_plat_dir="$the_liboqs_dir/build/export/$l_type/$the_liboqs_ver/$i_device/$i_arch"

  echo "BUILD: $l_type ($i_device / $i_arch)..."

  # locate back to script home
  cd "$the_top_dir" || return $?

  # create directory and clear - on errors we are done
  mkdir -p "$the_build_dir_path"/$l_type/$i_device/$i_arch
  cd "$the_build_dir_path/$l_type/$i_device/$i_arch" || return $?
  rm -fR ./*

  # the apple.cmake toolchain is managed by the liboqs team - so use it
  set -x
  liboqs_DIR="$the_liboqs_dir/build/$l_type/$i_device/$i_arch/src" \
  cmake \
    -DCMAKE_TOOLCHAIN_FILE="$the_cmake_dir_path"/apple.cmake  \
    -DPLATFORM=$i_platform \
    -DDEPLOYMENT_TARGET=$the_ios_target \
    -DOQS_PROVIDER_BUILD_STATIC=ON \
    -DOPENSSL_USE_STATIC_LIBS=ON \
    -DOPENSSL_ROOT_DIR="$l_openssl_plat_dir" \
    -DLIBOQS_INCLUDE_DIR="$l_liboqs_plat_dir/include" \
    "$the_top_dir"
  l_rc=$? ; set +x ; [ $l_rc -ne 0 ] && return $l_rc
  cmake --build . $the_cmake_build_verbose_option || return $?
  echo ''
  return 0
}

# build single fat apple library containing multiple architectures
function build_apple_fatlib {
  local i_device="$1" ; shift
  local i_archs="$1" ; shift
  local i_lib_name="$1" ; shift

  # local args
  local l_type='apple'
  local l_args=''
  local l_device_dir="$the_build_dir_path/$l_type/$i_device"

  echo "LIPO: $i_device / $i_lib_name..."

  # change to the device folder and create lib folder
  cd "$l_device_dir" || return $?
  mkdir -p ./lib
  [ ! -d ./lib ] && echo "Unable to create '$l_device_dir/lib'" && return 1

  # build args and execute
  for i_arch in `echo "$i_archs"` ; do
    l_args="${l_args}./$i_arch/lib/$i_lib_name "
  done
  eval xcrun lipo ${l_args}-create -output ./lib/$i_lib_name || return $?
  lipo -info ./lib/$i_lib_name
  ls -la ./lib/$i_lib_name
  echo ''
  return 0
}

# build multiple fat apple libraries containing multiple architectures
function build_apple_fatlibs {
  local i_device="$1" ; shift
  local i_archs="$1" ; shift
  local i_lib_names="$1" ; shift

  # call the helper function once per fatlib name
  for i_lib_name in `echo "$i_lib_names"` ; do
    build_apple_fatlib $i_device "$i_archs" $i_lib_name || return $?
  done
  return 0
}

# build standard set of fat apple libraries containing multiple architectures
function build_apple_fatlibs_std {
  local i_device="$1" ; shift
  local i_archs="$1" ; shift

  build_apple_fatlibs "$i_device" "$i_archs" 'oqsprovider.a' || return $?
  return 0
}

# build macox
function build_apple_macosx {
  local l_device='macosx'
  build_apple_variant $l_device x86_64 MAC || return $?
  build_apple_variant $l_device arm64 MAC_ARM64 || return $?
  build_apple_fatlibs_std $l_device 'x86_64 arm64' || return $?
  return 0
}

# build apple simulator
function build_apple_iphonesimulator {
  local l_device='iphonesimulator'
  build_apple_variant $l_device x86_64 SIMULATOR64 || return $?
  build_apple_variant $l_device arm64 SIMULATORARM64 || return $?
  build_apple_fatlibs_std $l_device 'x86_64 arm64' || return $?
  return 0
}

# build apple iphone
function build_apple_iphoneos {
  local l_device='iphoneos'
  build_apple_variant $l_device arm64 OS64 || return $?
  build_apple_fatlibs_std $l_device arm64 || return $?
  return 0
}

# build all known apple variants
function build_apple {
  build_apple_macosx || return $?
  build_apple_iphonesimulator || return $?
  build_apple_iphoneos || return $?
  return 0
}

##############################################################
# ANDROID build support
function build_android_variant {
  local i_arch="$1" ; shift

  # locals
  local l_rc=0
  local l_type='android'
  local l_openssl_plat_dir=$the_openssl_dir/$l_type/$the_openssl_ver/$i_arch
  local l_liboqs_plat_dir="$the_liboqs_dir/build/export/$l_type/$the_liboqs_ver/$i_arch"

  echo "BUILD: $l_type ($i_arch)..."

  # locate back to script home
  cd "$the_top_dir" || return $?

  # create directory and clear - on errors we are done
  mkdir -p "$the_build_dir_path"/$l_type/$i_arch
  cd "$the_build_dir_path"/$l_type/$i_arch || return $?
  rm -fR ./*

  # NOTES:
  # * we *must* use the Android NDK toolchain; it is not provided by liboqs
  # * default cmake toolchain fails with names like 'arm64-v8a' with dashes;
  #   this is why we *must set* OPENSSL_INCLUDE_DIR, OPENSSL_SSL_LIBRARY, OPENSSL_CRYPTO_LIBRARY
  set -x
  liboqs_DIR="$the_liboqs_dir/build/$l_type/$i_arch/src" \
  cmake \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME"/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=$i_arch \
    -DANDROID_PLATFORM=android-$the_android_api_level \
    -DOQS_PROVIDER_BUILD_STATIC=ON \
    -DOPENSSL_USE_STATIC_LIBS=ON \
    -DOPENSSL_ROOT_DIR="$l_openssl_plat_dir" \
    -DOPENSSL_INCLUDE_DIR="$l_openssl_plat_dir/include" \
    -DOPENSSL_SSL_LIBRARY="$l_openssl_plat_dir/lib/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$l_openssl_plat_dir/lib/libcrypto.a" \
    -DLIBOQS_INCLUDE_DIR="$l_liboqs_plat_dir/include" \
    "$the_top_dir"
  l_rc=$? ; set +x ; [ $l_rc -ne 0 ] && return $l_rc
  cmake --build . $the_cmake_build_verbose_option || return $?
  echo ''
  return 0
}

# build all known android variants
function build_android {
  # user can pass in the variant desired
  local l_variants='arm64-v8a x86_64 x86 armeabi-v7a'
  [ x"$1" != x ] && l_variants="$*"
  for i in `echo "$l_variants"` ; do
    build_android_variant $i || return $?
  done
  return 0
}

##############################################################
# EXPORT functions

# verify expected folder is created
function verify_folder {
  [ -d "$1" ] && return 0
  echo "ERROR: '$1' (missing required folder; rebuild necessary?)"
}

# verify all expected folders are created
function verify_folders {
  # locate back to script home
  cd "$the_top_dir" || return $?

  # note: 'include' folders are not generated by the build;
  # integration is driven by a single exported function:
  #   extern OSSL_provider_init_fn oqs_provider_init;

  # make sure that all known folders are created
  l_type='apple'
  verify_folder "$the_build_dir_path"/$l_type
  for l_device in iphoneos iphonesimulator macosx ; do
    verify_folder "$the_build_dir_path"/$l_type/$l_device
    verify_folder "$the_build_dir_path"/$l_type/$l_device/lib
    for l_arch in arm64 ; do
      verify_folder "$the_build_dir_path"/$l_type/$l_device/$l_arch
      #verify_folder "$the_build_dir_path"/$l_type/$l_device/$l_arch/include
    done
  done

  l_type='android'
  verify_folder "$the_build_dir_path"/$l_type
  for l_arch in arm64-v8a armeabi-v7a x86 x86_64 ; do
    verify_folder "$the_build_dir_path"/$l_type/$l_arch
    #verify_folder "$the_build_dir_path"/$l_type/$l_arch/include
    verify_folder "$the_build_dir_path"/$l_type/$l_arch/lib
  done

  return 0
}

# extract version from the generated compiled library
function get_oqs_provider_version {
  # must have all expected folders
  verify_folders || return $?

  # the version is provided as a CMake variable in root CMakeLists.txt
  local l_makelists="$the_top_dir/CMakeLists.txt"
  [ ! -s "$l_makelists" ] && echo "ERROR: Missing '$l_makelists'" && return 1
  local l_version="`cat "$l_makelists" | grep -e 'set(OQSPROVIDER_VERSION_TEXT' | awk '{print $2}' | tr -d '")' | xargs | dos2unix`"
  [ x"$l_version" = x ] && echo "ERROR: Unable to read OQSPROVIDER_VERSION_TEXT from '$l_makelists'" && return 1
  echo "$l_version"
  return 0
}

# create a single exported folder
function create_export_folder {
  local i_lib_dir="$1" ; shift
  local i_include_dir="$1" ; shift

  # library first
  mkdir -p "$the_export_dir_path/$i_lib_dir"
  [ ! -d "$the_export_dir_path/$i_lib_dir" ] && echo "ERROR: Missing '$the_export_dir_path/$i_lib_dir' (mkdir failure?)" && return 2
  rm -fR "$the_export_dir_path/$i_lib_dir"/* 
  cp -R "$the_build_dir_path/$i_lib_dir"/* "$the_export_dir_path/$i_lib_dir/" || return $?

  # now each include folder
  while [ x"$i_include_dir" != x ] ; do
    mkdir -p "$the_export_dir_path/$i_include_dir"
    [ ! -d "$the_export_dir_path/$i_include_dir" ] && echo "ERROR: Missing '$the_export_dir_path/$i_include_dir' (mkdir failure?)" && return 2
    rm -fR "$the_export_dir_path/$i_include_dir"/* 
    cp -R "$the_build_dir_path/$i_include_dir"/* "$the_export_dir_path/$i_include_dir/" || return $?

    # next include
    i_include_dir="$1" ; shift
  done

  return 0
}

# create single-level export folder to gather everything
function do_export {
  echo "EXPORT: Begin..."

  # locate back to script home
  cd "$the_top_dir" || return $?

  # get the version - error on failure
  local l_version=`get_oqs_provider_version`
  local l_rc=$?
  if [ $l_rc -ne 0 ] ; then
    # on error, l_version contains the failure message
    echo "$l_version"
    return $l_rc
  fi

  # create the export folder
  mkdir -p "$the_export_dir_path"
  cd "$the_export_dir_path" || return $?

  # load in from everything...
  create_export_folder android/arm64-v8a/lib || return $?
  create_export_folder android/armeabi-v7a/lib || return $?
  create_export_folder android/x86/lib || return $?
  create_export_folder android/x86_64/lib || return $?
  create_export_folder apple/iphoneos/lib || return $?
  create_export_folder apple/iphonesimulator/lib || return $?
  create_export_folder apple/macosx/lib || return $?

  # report on what was exported
  echo ''
  echo "VERSION: $l_version"
  find "$the_export_dir_path" -type d -name '*' -exec ls -lad {} \;
  find "$the_export_dir_path"/apple -type f -name '*.a' -exec lipo -info {} \;
  return 0
}

##############################################################
# PEP
function do_main {
  build_android || return $?
  build_apple || return $?
  do_export || return $?
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

