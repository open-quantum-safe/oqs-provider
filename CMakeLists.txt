cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(oqs-provider LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS ON)

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
