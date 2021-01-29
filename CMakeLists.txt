cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(oqs-provider LANGUAGES C)
set(CMAKE_C_STANDARD 90)

include(CheckLibraryExists)
include(CheckFunctionExists)

find_package(OpenSSL 3.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
## liboqs cmake config is lacking some data, so we must roll our own
#find_package(liboqs REQUIRED)
message("-- Looking for liboqs include directory")
find_path(liboqs_INCLUDE_DIR NAMES oqs/oqs.h REQUIRED)
message("-- Looking for liboqs include directory - found ${liboqs_INCLUDE_DIR}")
message("-- Looking for liboqs library")
find_library(liboqs_LIBRARY NAMES liboqs.a REQUIRED)
message("-- Looking for liboqs library - found ${liboqs_LIBRARY}")
include_directories(${liboqs_INCLUDE_DIR})

# Provider module
add_subdirectory(oqsprov)
