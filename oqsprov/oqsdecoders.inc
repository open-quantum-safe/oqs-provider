// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider decoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef DECODER_PROVIDER
#error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params "type-specific"
#define DECODER_STRUCTURE_type_specific "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub "type-specific"
#define DECODER_STRUCTURE_PKCS8 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo "PrivateKeyInfo"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                                        \
    {_name, "provider=" DECODER_PROVIDER ",input=" #_input,                    \
     (oqs_##_input##_to_##_output##_decoder_functions)}
#define DECODER_w_structure(_name, _input, _structure, _output)                \
    {_name,                                                                    \
     "provider=" DECODER_PROVIDER ",input=" #_input                            \
     ",structure=" DECODER_STRUCTURE_##_structure,                             \
     (oqs_##_structure##_##_input##_to_##_output##_decoder_functions)}

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
#ifdef OQS_KEM_ENCODERS

#ifdef OQS_ENABLE_KEM_efrodokem_640_aes
DECODER_w_structure("efrodo640aes", der, PrivateKeyInfo, efrodo640aes),
    DECODER_w_structure("efrodo640aes", der, SubjectPublicKeyInfo,
                        efrodo640aes),
    DECODER_w_structure("p256_efrodo640aes", der, PrivateKeyInfo,
                        p256_efrodo640aes),
    DECODER_w_structure("p256_efrodo640aes", der, SubjectPublicKeyInfo,
                        p256_efrodo640aes),
    DECODER_w_structure("x25519_efrodo640aes", der, PrivateKeyInfo,
                        x25519_efrodo640aes),
    DECODER_w_structure("x25519_efrodo640aes", der, SubjectPublicKeyInfo,
                        x25519_efrodo640aes),
#endif
#ifdef OQS_ENABLE_KEM_efrodokem_640_shake
    DECODER_w_structure("efrodo640shake", der, PrivateKeyInfo, efrodo640shake),
    DECODER_w_structure("efrodo640shake", der, SubjectPublicKeyInfo,
                        efrodo640shake),
    DECODER_w_structure("p256_efrodo640shake", der, PrivateKeyInfo,
                        p256_efrodo640shake),
    DECODER_w_structure("p256_efrodo640shake", der, SubjectPublicKeyInfo,
                        p256_efrodo640shake),
    DECODER_w_structure("x25519_efrodo640shake", der, PrivateKeyInfo,
                        x25519_efrodo640shake),
    DECODER_w_structure("x25519_efrodo640shake", der, SubjectPublicKeyInfo,
                        x25519_efrodo640shake),
#endif
#ifdef OQS_ENABLE_KEM_efrodokem_976_aes
    DECODER_w_structure("efrodo976aes", der, PrivateKeyInfo, efrodo976aes),
    DECODER_w_structure("efrodo976aes", der, SubjectPublicKeyInfo,
                        efrodo976aes),
    DECODER_w_structure("p384_efrodo976aes", der, PrivateKeyInfo,
                        p384_efrodo976aes),
    DECODER_w_structure("p384_efrodo976aes", der, SubjectPublicKeyInfo,
                        p384_efrodo976aes),
    DECODER_w_structure("x448_efrodo976aes", der, PrivateKeyInfo,
                        x448_efrodo976aes),
    DECODER_w_structure("x448_efrodo976aes", der, SubjectPublicKeyInfo,
                        x448_efrodo976aes),
#endif
#ifdef OQS_ENABLE_KEM_efrodokem_976_shake
    DECODER_w_structure("efrodo976shake", der, PrivateKeyInfo, efrodo976shake),
    DECODER_w_structure("efrodo976shake", der, SubjectPublicKeyInfo,
                        efrodo976shake),
    DECODER_w_structure("p384_efrodo976shake", der, PrivateKeyInfo,
                        p384_efrodo976shake),
    DECODER_w_structure("p384_efrodo976shake", der, SubjectPublicKeyInfo,
                        p384_efrodo976shake),
    DECODER_w_structure("x448_efrodo976shake", der, PrivateKeyInfo,
                        x448_efrodo976shake),
    DECODER_w_structure("x448_efrodo976shake", der, SubjectPublicKeyInfo,
                        x448_efrodo976shake),
#endif
#ifdef OQS_ENABLE_KEM_efrodokem_1344_aes
    DECODER_w_structure("efrodo1344aes", der, PrivateKeyInfo, efrodo1344aes),
    DECODER_w_structure("efrodo1344aes", der, SubjectPublicKeyInfo,
                        efrodo1344aes),
    DECODER_w_structure("p521_efrodo1344aes", der, PrivateKeyInfo,
                        p521_efrodo1344aes),
    DECODER_w_structure("p521_efrodo1344aes", der, SubjectPublicKeyInfo,
                        p521_efrodo1344aes),
#endif
#ifdef OQS_ENABLE_KEM_efrodokem_1344_shake
    DECODER_w_structure("efrodo1344shake", der, PrivateKeyInfo,
                        efrodo1344shake),
    DECODER_w_structure("efrodo1344shake", der, SubjectPublicKeyInfo,
                        efrodo1344shake),
    DECODER_w_structure("p521_efrodo1344shake", der, PrivateKeyInfo,
                        p521_efrodo1344shake),
    DECODER_w_structure("p521_efrodo1344shake", der, SubjectPublicKeyInfo,
                        p521_efrodo1344shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    DECODER_w_structure("frodo640aes", der, PrivateKeyInfo, frodo640aes),
    DECODER_w_structure("frodo640aes", der, SubjectPublicKeyInfo, frodo640aes),
    DECODER_w_structure("p256_frodo640aes", der, PrivateKeyInfo,
                        p256_frodo640aes),
    DECODER_w_structure("p256_frodo640aes", der, SubjectPublicKeyInfo,
                        p256_frodo640aes),
    DECODER_w_structure("x25519_frodo640aes", der, PrivateKeyInfo,
                        x25519_frodo640aes),
    DECODER_w_structure("x25519_frodo640aes", der, SubjectPublicKeyInfo,
                        x25519_frodo640aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    DECODER_w_structure("frodo640shake", der, PrivateKeyInfo, frodo640shake),
    DECODER_w_structure("frodo640shake", der, SubjectPublicKeyInfo,
                        frodo640shake),
    DECODER_w_structure("p256_frodo640shake", der, PrivateKeyInfo,
                        p256_frodo640shake),
    DECODER_w_structure("p256_frodo640shake", der, SubjectPublicKeyInfo,
                        p256_frodo640shake),
    DECODER_w_structure("x25519_frodo640shake", der, PrivateKeyInfo,
                        x25519_frodo640shake),
    DECODER_w_structure("x25519_frodo640shake", der, SubjectPublicKeyInfo,
                        x25519_frodo640shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    DECODER_w_structure("frodo976aes", der, PrivateKeyInfo, frodo976aes),
    DECODER_w_structure("frodo976aes", der, SubjectPublicKeyInfo, frodo976aes),
    DECODER_w_structure("p384_frodo976aes", der, PrivateKeyInfo,
                        p384_frodo976aes),
    DECODER_w_structure("p384_frodo976aes", der, SubjectPublicKeyInfo,
                        p384_frodo976aes),
    DECODER_w_structure("x448_frodo976aes", der, PrivateKeyInfo,
                        x448_frodo976aes),
    DECODER_w_structure("x448_frodo976aes", der, SubjectPublicKeyInfo,
                        x448_frodo976aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    DECODER_w_structure("frodo976shake", der, PrivateKeyInfo, frodo976shake),
    DECODER_w_structure("frodo976shake", der, SubjectPublicKeyInfo,
                        frodo976shake),
    DECODER_w_structure("p384_frodo976shake", der, PrivateKeyInfo,
                        p384_frodo976shake),
    DECODER_w_structure("p384_frodo976shake", der, SubjectPublicKeyInfo,
                        p384_frodo976shake),
    DECODER_w_structure("x448_frodo976shake", der, PrivateKeyInfo,
                        x448_frodo976shake),
    DECODER_w_structure("x448_frodo976shake", der, SubjectPublicKeyInfo,
                        x448_frodo976shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    DECODER_w_structure("frodo1344aes", der, PrivateKeyInfo, frodo1344aes),
    DECODER_w_structure("frodo1344aes", der, SubjectPublicKeyInfo,
                        frodo1344aes),
    DECODER_w_structure("p521_frodo1344aes", der, PrivateKeyInfo,
                        p521_frodo1344aes),
    DECODER_w_structure("p521_frodo1344aes", der, SubjectPublicKeyInfo,
                        p521_frodo1344aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    DECODER_w_structure("frodo1344shake", der, PrivateKeyInfo, frodo1344shake),
    DECODER_w_structure("frodo1344shake", der, SubjectPublicKeyInfo,
                        frodo1344shake),
    DECODER_w_structure("p521_frodo1344shake", der, PrivateKeyInfo,
                        p521_frodo1344shake),
    DECODER_w_structure("p521_frodo1344shake", der, SubjectPublicKeyInfo,
                        p521_frodo1344shake),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    DECODER_w_structure("bikel1", der, PrivateKeyInfo, bikel1),
    DECODER_w_structure("bikel1", der, SubjectPublicKeyInfo, bikel1),
    DECODER_w_structure("p256_bikel1", der, PrivateKeyInfo, p256_bikel1),
    DECODER_w_structure("p256_bikel1", der, SubjectPublicKeyInfo, p256_bikel1),
    DECODER_w_structure("x25519_bikel1", der, PrivateKeyInfo, x25519_bikel1),
    DECODER_w_structure("x25519_bikel1", der, SubjectPublicKeyInfo,
                        x25519_bikel1),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    DECODER_w_structure("bikel3", der, PrivateKeyInfo, bikel3),
    DECODER_w_structure("bikel3", der, SubjectPublicKeyInfo, bikel3),
    DECODER_w_structure("p384_bikel3", der, PrivateKeyInfo, p384_bikel3),
    DECODER_w_structure("p384_bikel3", der, SubjectPublicKeyInfo, p384_bikel3),
    DECODER_w_structure("x448_bikel3", der, PrivateKeyInfo, x448_bikel3),
    DECODER_w_structure("x448_bikel3", der, SubjectPublicKeyInfo, x448_bikel3),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    DECODER_w_structure("bikel5", der, PrivateKeyInfo, bikel5),
    DECODER_w_structure("bikel5", der, SubjectPublicKeyInfo, bikel5),
    DECODER_w_structure("p521_bikel5", der, PrivateKeyInfo, p521_bikel5),
    DECODER_w_structure("p521_bikel5", der, SubjectPublicKeyInfo, p521_bikel5),
#endif
#ifdef OQS_ENABLE_KEM_hqc_1
    DECODER_w_structure("hqc1", der, PrivateKeyInfo, hqc1),
    DECODER_w_structure("hqc1", der, SubjectPublicKeyInfo, hqc1),
    DECODER_w_structure("p256_hqc1", der, PrivateKeyInfo, p256_hqc1),
    DECODER_w_structure("p256_hqc1", der, SubjectPublicKeyInfo, p256_hqc1),
    DECODER_w_structure("x25519_hqc1", der, PrivateKeyInfo, x25519_hqc1),
    DECODER_w_structure("x25519_hqc1", der, SubjectPublicKeyInfo, x25519_hqc1),
#endif
#ifdef OQS_ENABLE_KEM_hqc_3
    DECODER_w_structure("hqc3", der, PrivateKeyInfo, hqc3),
    DECODER_w_structure("hqc3", der, SubjectPublicKeyInfo, hqc3),
    DECODER_w_structure("p384_hqc3", der, PrivateKeyInfo, p384_hqc3),
    DECODER_w_structure("p384_hqc3", der, SubjectPublicKeyInfo, p384_hqc3),
    DECODER_w_structure("x448_hqc3", der, PrivateKeyInfo, x448_hqc3),
    DECODER_w_structure("x448_hqc3", der, SubjectPublicKeyInfo, x448_hqc3),
#endif
#ifdef OQS_ENABLE_KEM_hqc_5
    DECODER_w_structure("hqc5", der, PrivateKeyInfo, hqc5),
    DECODER_w_structure("hqc5", der, SubjectPublicKeyInfo, hqc5),
    DECODER_w_structure("p521_hqc5", der, PrivateKeyInfo, p521_hqc5),
    DECODER_w_structure("p521_hqc5", der, SubjectPublicKeyInfo, p521_hqc5),
#endif

#endif /* OQS_KEM_ENCODERS */

#ifdef OQS_ENABLE_SIG_falcon_512
    DECODER_w_structure("falcon512", der, PrivateKeyInfo, falcon512),
    DECODER_w_structure("falcon512", der, SubjectPublicKeyInfo, falcon512),
    DECODER_w_structure("p256_falcon512", der, PrivateKeyInfo, p256_falcon512),
    DECODER_w_structure("p256_falcon512", der, SubjectPublicKeyInfo,
                        p256_falcon512),
    DECODER_w_structure("rsa3072_falcon512", der, PrivateKeyInfo,
                        rsa3072_falcon512),
    DECODER_w_structure("rsa3072_falcon512", der, SubjectPublicKeyInfo,
                        rsa3072_falcon512),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_512
    DECODER_w_structure("falconpadded512", der, PrivateKeyInfo,
                        falconpadded512),
    DECODER_w_structure("falconpadded512", der, SubjectPublicKeyInfo,
                        falconpadded512),
    DECODER_w_structure("p256_falconpadded512", der, PrivateKeyInfo,
                        p256_falconpadded512),
    DECODER_w_structure("p256_falconpadded512", der, SubjectPublicKeyInfo,
                        p256_falconpadded512),
    DECODER_w_structure("rsa3072_falconpadded512", der, PrivateKeyInfo,
                        rsa3072_falconpadded512),
    DECODER_w_structure("rsa3072_falconpadded512", der, SubjectPublicKeyInfo,
                        rsa3072_falconpadded512),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    DECODER_w_structure("falcon1024", der, PrivateKeyInfo, falcon1024),
    DECODER_w_structure("falcon1024", der, SubjectPublicKeyInfo, falcon1024),
    DECODER_w_structure("p521_falcon1024", der, PrivateKeyInfo,
                        p521_falcon1024),
    DECODER_w_structure("p521_falcon1024", der, SubjectPublicKeyInfo,
                        p521_falcon1024),
#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_1024
    DECODER_w_structure("falconpadded1024", der, PrivateKeyInfo,
                        falconpadded1024),
    DECODER_w_structure("falconpadded1024", der, SubjectPublicKeyInfo,
                        falconpadded1024),
    DECODER_w_structure("p521_falconpadded1024", der, PrivateKeyInfo,
                        p521_falconpadded1024),
    DECODER_w_structure("p521_falconpadded1024", der, SubjectPublicKeyInfo,
                        p521_falconpadded1024),
#endif
#ifdef OQS_ENABLE_SIG_mayo_1
    DECODER_w_structure("mayo1", der, PrivateKeyInfo, mayo1),
    DECODER_w_structure("mayo1", der, SubjectPublicKeyInfo, mayo1),
    DECODER_w_structure("p256_mayo1", der, PrivateKeyInfo, p256_mayo1),
    DECODER_w_structure("p256_mayo1", der, SubjectPublicKeyInfo, p256_mayo1),
#endif
#ifdef OQS_ENABLE_SIG_mayo_2
    DECODER_w_structure("mayo2", der, PrivateKeyInfo, mayo2),
    DECODER_w_structure("mayo2", der, SubjectPublicKeyInfo, mayo2),
    DECODER_w_structure("p256_mayo2", der, PrivateKeyInfo, p256_mayo2),
    DECODER_w_structure("p256_mayo2", der, SubjectPublicKeyInfo, p256_mayo2),
#endif
#ifdef OQS_ENABLE_SIG_mayo_3
    DECODER_w_structure("mayo3", der, PrivateKeyInfo, mayo3),
    DECODER_w_structure("mayo3", der, SubjectPublicKeyInfo, mayo3),
    DECODER_w_structure("p384_mayo3", der, PrivateKeyInfo, p384_mayo3),
    DECODER_w_structure("p384_mayo3", der, SubjectPublicKeyInfo, p384_mayo3),
#endif
#ifdef OQS_ENABLE_SIG_mayo_5
    DECODER_w_structure("mayo5", der, PrivateKeyInfo, mayo5),
    DECODER_w_structure("mayo5", der, SubjectPublicKeyInfo, mayo5),
    DECODER_w_structure("p521_mayo5", der, PrivateKeyInfo, p521_mayo5),
    DECODER_w_structure("p521_mayo5", der, SubjectPublicKeyInfo, p521_mayo5),
#endif
#ifdef OQS_ENABLE_SIG_cross_rsdp_128_balanced
    DECODER_w_structure("CROSSrsdp128balanced", der, PrivateKeyInfo,
                        CROSSrsdp128balanced),
    DECODER_w_structure("CROSSrsdp128balanced", der, SubjectPublicKeyInfo,
                        CROSSrsdp128balanced),
#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Is_pkc
    DECODER_w_structure("OV_Is_pkc", der, PrivateKeyInfo, OV_Is_pkc),
    DECODER_w_structure("OV_Is_pkc", der, SubjectPublicKeyInfo, OV_Is_pkc),
    DECODER_w_structure("p256_OV_Is_pkc", der, PrivateKeyInfo, p256_OV_Is_pkc),
    DECODER_w_structure("p256_OV_Is_pkc", der, SubjectPublicKeyInfo,
                        p256_OV_Is_pkc),
#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Ip_pkc
    DECODER_w_structure("OV_Ip_pkc", der, PrivateKeyInfo, OV_Ip_pkc),
    DECODER_w_structure("OV_Ip_pkc", der, SubjectPublicKeyInfo, OV_Ip_pkc),
    DECODER_w_structure("p256_OV_Ip_pkc", der, PrivateKeyInfo, p256_OV_Ip_pkc),
    DECODER_w_structure("p256_OV_Ip_pkc", der, SubjectPublicKeyInfo,
                        p256_OV_Ip_pkc),
#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Is_pkc_skc
    DECODER_w_structure("OV_Is_pkc_skc", der, PrivateKeyInfo, OV_Is_pkc_skc),
    DECODER_w_structure("OV_Is_pkc_skc", der, SubjectPublicKeyInfo,
                        OV_Is_pkc_skc),
    DECODER_w_structure("p256_OV_Is_pkc_skc", der, PrivateKeyInfo,
                        p256_OV_Is_pkc_skc),
    DECODER_w_structure("p256_OV_Is_pkc_skc", der, SubjectPublicKeyInfo,
                        p256_OV_Is_pkc_skc),
#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc
    DECODER_w_structure("OV_Ip_pkc_skc", der, PrivateKeyInfo, OV_Ip_pkc_skc),
    DECODER_w_structure("OV_Ip_pkc_skc", der, SubjectPublicKeyInfo,
                        OV_Ip_pkc_skc),
    DECODER_w_structure("p256_OV_Ip_pkc_skc", der, PrivateKeyInfo,
                        p256_OV_Ip_pkc_skc),
    DECODER_w_structure("p256_OV_Ip_pkc_skc", der, SubjectPublicKeyInfo,
                        p256_OV_Ip_pkc_skc),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_K
    DECODER_w_structure("snova1k", der, PrivateKeyInfo, snova1k),
    DECODER_w_structure("snova1k", der, SubjectPublicKeyInfo, snova1k),
    DECODER_w_structure("p256_snova1k", der, PrivateKeyInfo, p256_snova1k),
    DECODER_w_structure("p256_snova1k", der, SubjectPublicKeyInfo,
                        p256_snova1k),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_B
    DECODER_w_structure("snova1b", der, PrivateKeyInfo, snova1b),
    DECODER_w_structure("snova1b", der, SubjectPublicKeyInfo, snova1b),
    DECODER_w_structure("p256_snova1b", der, PrivateKeyInfo, p256_snova1b),
    DECODER_w_structure("p256_snova1b", der, SubjectPublicKeyInfo,
                        p256_snova1b),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_S
    DECODER_w_structure("snova1s", der, PrivateKeyInfo, snova1s),
    DECODER_w_structure("snova1s", der, SubjectPublicKeyInfo, snova1s),
    DECODER_w_structure("p256_snova1s", der, PrivateKeyInfo, p256_snova1s),
    DECODER_w_structure("p256_snova1s", der, SubjectPublicKeyInfo,
                        p256_snova1s),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_K
    DECODER_w_structure("snova3k", der, PrivateKeyInfo, snova3k),
    DECODER_w_structure("snova3k", der, SubjectPublicKeyInfo, snova3k),
    DECODER_w_structure("p384_snova3k", der, PrivateKeyInfo, p384_snova3k),
    DECODER_w_structure("p384_snova3k", der, SubjectPublicKeyInfo,
                        p384_snova3k),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_B
    DECODER_w_structure("snova3b", der, PrivateKeyInfo, snova3b),
    DECODER_w_structure("snova3b", der, SubjectPublicKeyInfo, snova3b),
    DECODER_w_structure("p384_snova3b", der, PrivateKeyInfo, p384_snova3b),
    DECODER_w_structure("p384_snova3b", der, SubjectPublicKeyInfo,
                        p384_snova3b),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_S
    DECODER_w_structure("snova3s", der, PrivateKeyInfo, snova3s),
    DECODER_w_structure("snova3s", der, SubjectPublicKeyInfo, snova3s),
    DECODER_w_structure("p384_snova3s", der, PrivateKeyInfo, p384_snova3s),
    DECODER_w_structure("p384_snova3s", der, SubjectPublicKeyInfo,
                        p384_snova3s),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_K
    DECODER_w_structure("snova5k", der, PrivateKeyInfo, snova5k),
    DECODER_w_structure("snova5k", der, SubjectPublicKeyInfo, snova5k),
    DECODER_w_structure("p521_snova5k", der, PrivateKeyInfo, p521_snova5k),
    DECODER_w_structure("p521_snova5k", der, SubjectPublicKeyInfo,
                        p521_snova5k),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_B
    DECODER_w_structure("snova5b", der, PrivateKeyInfo, snova5b),
    DECODER_w_structure("snova5b", der, SubjectPublicKeyInfo, snova5b),
    DECODER_w_structure("p521_snova5b", der, PrivateKeyInfo, p521_snova5b),
    DECODER_w_structure("p521_snova5b", der, SubjectPublicKeyInfo,
                        p521_snova5b),
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_S
    DECODER_w_structure("snova5s", der, PrivateKeyInfo, snova5s),
    DECODER_w_structure("snova5s", der, SubjectPublicKeyInfo, snova5s),
    DECODER_w_structure("p521_snova5s", der, PrivateKeyInfo, p521_snova5s),
    DECODER_w_structure("p521_snova5s", der, SubjectPublicKeyInfo,
                        p521_snova5s),
#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat1_gf16_fast_ct
    DECODER_w_structure("mqom3cat1gf16fastct", der, PrivateKeyInfo,
                        mqom3cat1gf16fastct),
    DECODER_w_structure("mqom3cat1gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat1gf16fastct),
    DECODER_w_structure("p256_mqom3cat1gf16fastct", der, PrivateKeyInfo,
                        p256_mqom3cat1gf16fastct),
    DECODER_w_structure("p256_mqom3cat1gf16fastct", der, SubjectPublicKeyInfo,
                        p256_mqom3cat1gf16fastct),
#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat3_gf16_fast_ct
    DECODER_w_structure("mqom3cat3gf16fastct", der, PrivateKeyInfo,
                        mqom3cat3gf16fastct),
    DECODER_w_structure("mqom3cat3gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat3gf16fastct),
    DECODER_w_structure("p384_mqom3cat3gf16fastct", der, PrivateKeyInfo,
                        p384_mqom3cat3gf16fastct),
    DECODER_w_structure("p384_mqom3cat3gf16fastct", der, SubjectPublicKeyInfo,
                        p384_mqom3cat3gf16fastct),
#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat5_gf16_fast_ct
    DECODER_w_structure("mqom3cat5gf16fastct", der, PrivateKeyInfo,
                        mqom3cat5gf16fastct),
    DECODER_w_structure("mqom3cat5gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat5gf16fastct),
    DECODER_w_structure("p521_mqom3cat5gf16fastct", der, PrivateKeyInfo,
                        p521_mqom3cat5gf16fastct),
    DECODER_w_structure("p521_mqom3cat5gf16fastct", der, SubjectPublicKeyInfo,
                        p521_mqom3cat5gf16fastct),
#endif
    ///// OQS_TEMPLATE_FRAGMENT_MAKE_END
