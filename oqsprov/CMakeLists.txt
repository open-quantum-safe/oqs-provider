add_compile_options(-Wunused-function)
set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_groups.c oqsprov_keys.c
  oqs_kmgmt.c oqs_sig.c oqs_kem.c
  oqs_encode_key2any.c oqs_endecoder_common.c oqs_decode_der2key.c oqsprov_bio.c
)
set(PROVIDER_HEADER_FILES
  oqs_prov.h oqs_endecoder_local.h
)
add_library(oqsprovider MODULE ${PROVIDER_SOURCE_FILES})
set_target_properties(oqsprovider
  PROPERTIES PREFIX "" OUTPUT_NAME "oqsprovider"
)
target_link_libraries(oqsprovider OQS::oqs ${OPENSSL_CRYPTO_LIBRARY})
