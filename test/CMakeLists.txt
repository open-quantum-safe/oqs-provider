include(GNUInstallDirs)
add_test(
  NAME oqs_signatures
  COMMAND oqs_test_signatures
          "oqsprovider"
          "${CMAKE_SOURCE_DIR}/test/oqs.cnf"
)
set_tests_properties(oqs_signatures
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/lib"
)

add_executable(oqs_test_signatures oqs_test_signatures.c test_common.c)
target_include_directories(oqs_test_signatures PRIVATE ${CMAKE_SOURCE_DIR}/.local/include)
target_link_libraries(oqs_test_signatures ${OPENSSL_CRYPTO_LIBRARY})

add_test(
  NAME oqs_kems
  COMMAND oqs_test_kems
          "oqsprovider"
          "${CMAKE_SOURCE_DIR}/test/oqs.cnf"
)
set_tests_properties(oqs_kems
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/lib"
)

add_executable(oqs_test_kems oqs_test_kems.c test_common.c)
target_include_directories(oqs_test_kems PRIVATE ${CMAKE_SOURCE_DIR}/.local/include)
target_link_libraries(oqs_test_kems ${OPENSSL_CRYPTO_LIBRARY})

if (DEFINED OPENSSL_SRCTOP)
    if (NOT DEFINED OPENSSL_BLDTOP)
        set(OPENSSL_BLDTOP "${OPENSSL_SRCTOP}")
    endif()
else()
    if (NOT DEFINED OPENSSL_BLDTOP)
        set(OPENSSL_BLDTOP "${CMAKE_CURRENT_SOURCE_DIR}/../openssl")
    endif()
    set(OPENSSL_SRCTOP "${OPENSSL_BLDTOP}")
endif()

if (NOT IS_DIRECTORY ${OPENSSL_SRCTOP})
    message(WARNING "OpenSSL source directory '${OPENSSL_SRCTOP}' not present. Some dependent tests will be skipped.") 
elseif (NOT IS_DIRECTORY ${OPENSSL_BLDTOP})
    message(WARNING "OpenSSL build directory '${OPENSSL_BLDTOP}' not present. Some dependent tests will be skipped.") 
else()
add_test(
    NAME oqs_groups
    COMMAND oqs_test_groups
            "oqsprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs.cnf"
            "${OPENSSL_SRCTOP}/test/certs"
            "${OPENSSL_SRCTOP}/test/recipes/90-test_sslapi_data/passwd.txt"
)
set_tests_properties(oqs_groups
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/lib"
)
add_executable(oqs_test_groups oqs_test_groups.c test_common.c tlstest_helpers.c)
target_link_libraries(oqs_test_groups ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

add_test(
    NAME oqs_tlssig
    COMMAND oqs_test_tlssig
            "oqsprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs.cnf"
            "${CMAKE_CURRENT_SOURCE_DIR}/../tmp"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(oqs_tlssig
    # Some algorithms known to overflow OpenSSL limits; TBD/resolved upstream
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/lib;OQS_SKIP_TESTS=picnicl1full,rainbowVclassic,sphincs"
)
add_executable(oqs_test_tlssig oqs_test_tlssig.c test_common.c tlstest_helpers.c)
target_link_libraries(oqs_test_tlssig ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

add_executable(oqs_test_endecode oqs_test_endecode.c test_common.c)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_SRCTOP}/include)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_SRCTOP}/test)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_SRCTOP}/apps/include)

target_link_libraries(oqs_test_endecode ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_BLDTOP}/test/libtestutil.a )
add_test(
  NAME oqs_endecode
  COMMAND oqs_test_endecode
)
set_tests_properties(oqs_endecode
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/lib"
)

endif() # NOT IS_DIRECTORY ${OPENSSL_BLDTOP}

