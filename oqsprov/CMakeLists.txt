set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_groups.c oqsprov_keys.c
  oqs_kmgmt.c oqs_sig.c oqs_kem.c
)
set(PROVIDER_HEADER_FILES
  oqsx.h
)
add_library(oqsprovider MODULE ${PROVIDER_SOURCE_FILES})
set_target_properties(oqsprovider
  PROPERTIES PREFIX "" OUTPUT_NAME "oqsprovider"
)
target_link_libraries(oqsprovider ${liboqs_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
# To link weird mceliece avx code:
target_link_options(oqs PRIVATE -Wl,-Bsymbolic)
