include(GNUInstallDirs)
add_definitions(-DOQSPROVIDER_VERSION_TEXT="${OQSPROVIDER_VERSION_TEXT}")
add_compile_options(-Wunused-function)
set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_capabilities.c oqsprov_keys.c
  oqs_kmgmt.c oqs_sig.c oqs_kem.c
  oqs_encode_key2any.c oqs_endecoder_common.c oqs_decode_der2key.c oqsprov_bio.c
  oqsprov.def
)
set(PROVIDER_HEADER_FILES
  oqs_prov.h oqs_endecoder_local.h
)
add_library(oqsprovider MODULE ${PROVIDER_SOURCE_FILES})
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
install(TARGETS oqsprovider
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}")
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VENDOR "www.openquantumsafe.org")
set(CPACK_PACKAGE_VERSION ${OQSPROVIDER_VERSION_TEXT})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, openssl (>= 3.0.0)")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "www.openquantumsafe.org")
include(CPack)

