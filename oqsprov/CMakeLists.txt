include(GNUInstallDirs)
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (USE_ENCODING_LIB)
  include(ExternalProject)
  set(encoder_LIBRARY ${CMAKE_BINARY_DIR}/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}qsc_key_encoder${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(encoder_LIBRARY_INCLUDE ${CMAKE_BINARY_DIR}/install/include)
  ExternalProject_Add(encoder
      GIT_REPOSITORY https://github.com/Quantum-Safe-Collaboration/qsc-key-encoder.git
      GIT_TAG main
      CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/install -DCMAKE_BUILD_TYPE=Release
      UPDATE_DISCONNECTED 1
      BUILD_BYPRODUCTS ${encoder_LIBRARY}
  )
  add_library(qsc_key_encoder STATIC IMPORTED)
  set_target_properties(qsc_key_encoder PROPERTIES IMPORTED_LOCATION ${encoder_LIBRARY})
endif()
add_definitions(-DOQSPROVIDER_VERSION_TEXT="${OQSPROVIDER_VERSION_TEXT}")
message(STATUS "Building commit ${GIT_COMMIT_HASH} in ${CMAKE_SOURCE_DIR}")
add_definitions(-DOQS_PROVIDER_COMMIT=" \(${GIT_COMMIT_HASH}\)")
if (NOT WIN32)
add_compile_options(-Wunused-function)
endif()
set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_capabilities.c oqsprov_keys.c
  oqs_kmgmt.c oqs_sig.c oqs_kem.c
  oqs_encode_key2any.c oqs_endecoder_common.c oqs_decode_der2key.c oqsprov_bio.c
  oqsprov.def
)
set(PROVIDER_HEADER_FILES
  oqs_prov.h oqs_endecoder_local.h
)
add_library(oqsprovider SHARED ${PROVIDER_SOURCE_FILES})
if (USE_ENCODING_LIB)
  add_dependencies(oqsprovider encoder)
endif()
set_target_properties(oqsprovider
    PROPERTIES
    PREFIX ""
    OUTPUT_NAME "oqsprovider"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION ${OQSPROVIDER_VERSION_TEXT}
    SOVERSION 1
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_link_libraries(oqsprovider OQS::oqs ${OPENSSL_CRYPTO_LIBRARY})
if (USE_ENCODING_LIB)
  target_link_libraries(oqsprovider qsc_key_encoder)
  target_include_directories(oqsprovider PRIVATE ${encoder_LIBRARY_INCLUDE})
endif()
install(TARGETS oqsprovider
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}")
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VENDOR "www.openquantumsafe.org")
set(CPACK_PACKAGE_VERSION ${OQSPROVIDER_VERSION_TEXT})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, openssl (>= 3.0.0)")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "www.openquantumsafe.org")
include(CPack)

