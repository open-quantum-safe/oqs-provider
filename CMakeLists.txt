cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(oqs-provider LANGUAGES C)
set(OQSPROVIDER_VERSION_TEXT "0.5.1-dev")
set(CMAKE_C_STANDARD 11)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS ON)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Creating Debug build with OQS-Debug env vars enabled")
else()
    message(STATUS "Creating Release build")
    add_definitions( -DNDEBUG )
endif()

if(MSVC)
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:LIBCMT")
  add_definitions(-DOQS_PROVIDER_NOATOMIC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wunused-function)
endif()

option(NOPUBKEY_IN_PRIVKEY "Do not include public keys in private key structures/PKCS#8 " OFF)
if(${NOPUBKEY_IN_PRIVKEY})
    message(STATUS "Build will not store public keys alongside private keys in PKCS#8 structures")
    add_compile_definitions( NOPUBKEY_IN_PRIVKEY )
else()
    message(STATUS "Build will store public keys in PKCS#8 structures")
endif()
option(USE_ENCODING_LIB "Build with external encoding library for SPKI/PKCS#8 " OFF)
if(${USE_ENCODING_LIB})
    message(STATUS "Build will include external encoding library for SPKI/PKCS#8")
    add_compile_definitions( USE_ENCODING_LIB )
else()
    message(STATUS "Build will not include external encoding library for SPKI/PKCS#8")
endif()

include(CheckLibraryExists)
include(CheckFunctionExists)

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
find_package(liboqs REQUIRED)

# Provider module
add_subdirectory(oqsprov)

# Testing
enable_testing()
add_subdirectory(test)
