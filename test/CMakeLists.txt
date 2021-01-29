add_test(
  NAME oqs_signatures
  COMMAND oqs_test_signatures
          "oqsprovider"
          "${CMAKE_SOURCE_DIR}/test/oqs.cnf"
)
set_tests_properties(oqs_signatures
  PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
)

add_executable(oqs_test_signatures oqs_test_signatures.c)
target_link_libraries(oqs_test_signatures ${OPENSSL_CRYPTO_LIBRARY})

# oqs_test_groups.c relies on OpenSSL internals, which must be copied to
# this directory to run this test:
#
#    {openssl}/test/helpers/ssltestlib.c        -> test/ssltestlib.c
#    {openssl}/test/helpers/ssltestlib.h        -> test/ssltestlib.h
#    (they need some work to make independent from OpenSSL, patches are
#     available in test/ssltestlib.c.patch and test/ssltestlib.h.patch)
#
#    {openssl}/test/certs/                      -> test/oqs_test_groups/certs/
#    (just copy the whole directory over as is)
#
#    {openssl}/test/recipes/90-test_sslapi_data/passwd.txt
#                                               -> test/oqs_test_groups/passwd.txt
if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ssltestlib.h
    AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/ssltestlib.c
    AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/oqs_test_groups/passwd.txt
    AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/oqs_test_groups/certs
    AND IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/oqs_test_groups/certs)
  message("-- Including test oqs_groups")
  add_test(
    NAME oqs_groups
    COMMAND oqs_test_groups
            "oqsprovider"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs.cnf"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs_test_groups/certs"
            "${CMAKE_CURRENT_SOURCE_DIR}/oqs_test_groups/passwd.txt"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test-groups
  )
  set_tests_properties(oqs_signatures oqs_groups
    PROPERTIES ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}/oqsprov"
  )
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/test-groups)
  add_executable(oqs_test_groups oqs_test_groups.c ssltestlib.c)
  target_link_libraries(oqs_test_groups ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
endif()
