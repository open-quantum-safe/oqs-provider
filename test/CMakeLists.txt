add_test(
  NAME oqs_signatures
  COMMAND oqs_test_signatures
          "oqsprovider"
          "${CMAKE_SOURCE_DIR}/test/oqs.cnf"
)
set_tests_properties(oqs_signatures
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
)

add_executable(oqs_test_signatures oqs_test_signatures.c test_common.c)
target_link_libraries(oqs_test_signatures ${OPENSSL_CRYPTO_LIBRARY})

add_test(
  NAME oqs_kems
  COMMAND oqs_test_kems
          "oqsprovider"
          "${CMAKE_SOURCE_DIR}/test/oqs.cnf"
)
set_tests_properties(oqs_kems
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
)

add_executable(oqs_test_kems oqs_test_kems.c test_common.c)
target_link_libraries(oqs_test_kems ${OPENSSL_CRYPTO_LIBRARY})

if (NOT DEFINED OPENSSL_BLDTOP)
   set(OPENSSL_BLDTOP "${CMAKE_CURRENT_SOURCE_DIR}/../openssl")
endif()

if (NOT IS_DIRECTORY ${OPENSSL_BLDTOP})
    message(WARNING "OpenSSL build directory '${OPENSSL_BLDTOP}' not present. Some dependent tests will be skipped.") 
else()
add_test(
    NAME oqs_groups
    COMMAND oqs_test_groups
            "oqsprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs.cnf"
            "${OPENSSL_BLDTOP}/test/certs"
            "${OPENSSL_BLDTOP}/test/recipes/90-test_sslapi_data/passwd.txt"
)
set_tests_properties(oqs_groups
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
)
add_executable(oqs_test_groups oqs_test_groups.c test_common.c ${OPENSSL_BLDTOP}/test/helpers/ssltestlib.c)
# e_os.h resides in top-level for OSSL3:
target_include_directories(oqs_test_groups PRIVATE ${OPENSSL_BLDTOP})
target_include_directories(oqs_test_groups PRIVATE ${OPENSSL_BLDTOP}/include)
target_include_directories(oqs_test_groups PRIVATE ${OPENSSL_BLDTOP}/test)
target_include_directories(oqs_test_groups PRIVATE ${OPENSSL_BLDTOP}/apps/include)
target_link_libraries(oqs_test_groups ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_BLDTOP}/test/libtestutil.a)

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
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov;OQS_SKIP_TESTS=picnicl1full,rainbowVclassic,sphincs"
)
add_executable(oqs_test_tlssig oqs_test_tlssig.c test_common.c ${OPENSSL_BLDTOP}/test/helpers/ssltestlib.c)
# e_os.h resides in top-level for OSSL3:
target_include_directories(oqs_test_tlssig PRIVATE ${OPENSSL_BLDTOP})
target_include_directories(oqs_test_tlssig PRIVATE ${OPENSSL_BLDTOP}/include)
target_include_directories(oqs_test_tlssig PRIVATE ${OPENSSL_BLDTOP}/test)
target_include_directories(oqs_test_tlssig PRIVATE ${OPENSSL_BLDTOP}/apps/include)
target_link_libraries(oqs_test_tlssig ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_BLDTOP}/test/libtestutil.a)

add_executable(oqs_test_endecode oqs_test_endecode.c test_common.c)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_BLDTOP}/include)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_BLDTOP}/test)
target_include_directories(oqs_test_endecode PRIVATE ${OPENSSL_BLDTOP}/apps/include)

target_link_libraries(oqs_test_endecode ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_BLDTOP}/test/libtestutil.a )
add_test(
  NAME oqs_endecode
  COMMAND oqs_test_endecode
)
set_tests_properties(oqs_endecode
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
)

endif() # NOT IS_DIRECTORY ${OPENSSL_BLDTOP}

