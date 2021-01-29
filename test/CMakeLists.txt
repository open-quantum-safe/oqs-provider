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
