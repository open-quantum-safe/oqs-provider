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

#endif
#ifdef OQS_ENABLE_KEM_efrodokem_640_shake
    DECODER_w_structure("efrodo640shake", der, PrivateKeyInfo, efrodo640shake),
    DECODER_w_structure("efrodo640shake", der, SubjectPublicKeyInfo,
                        efrodo640shake),

#endif
#ifdef OQS_ENABLE_KEM_efrodokem_976_aes
    DECODER_w_structure("efrodo976aes", der, PrivateKeyInfo, efrodo976aes),
    DECODER_w_structure("efrodo976aes", der, SubjectPublicKeyInfo,
                        efrodo976aes),

#endif
#ifdef OQS_ENABLE_KEM_efrodokem_976_shake
    DECODER_w_structure("efrodo976shake", der, PrivateKeyInfo, efrodo976shake),
    DECODER_w_structure("efrodo976shake", der, SubjectPublicKeyInfo,
                        efrodo976shake),

#endif
#ifdef OQS_ENABLE_KEM_efrodokem_1344_aes
    DECODER_w_structure("efrodo1344aes", der, PrivateKeyInfo, efrodo1344aes),
    DECODER_w_structure("efrodo1344aes", der, SubjectPublicKeyInfo,
                        efrodo1344aes),

#endif
#ifdef OQS_ENABLE_KEM_efrodokem_1344_shake
    DECODER_w_structure("efrodo1344shake", der, PrivateKeyInfo,
                        efrodo1344shake),
    DECODER_w_structure("efrodo1344shake", der, SubjectPublicKeyInfo,
                        efrodo1344shake),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    DECODER_w_structure("frodo640aes", der, PrivateKeyInfo, frodo640aes),
    DECODER_w_structure("frodo640aes", der, SubjectPublicKeyInfo, frodo640aes),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    DECODER_w_structure("frodo640shake", der, PrivateKeyInfo, frodo640shake),
    DECODER_w_structure("frodo640shake", der, SubjectPublicKeyInfo,
                        frodo640shake),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    DECODER_w_structure("frodo976aes", der, PrivateKeyInfo, frodo976aes),
    DECODER_w_structure("frodo976aes", der, SubjectPublicKeyInfo, frodo976aes),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    DECODER_w_structure("frodo976shake", der, PrivateKeyInfo, frodo976shake),
    DECODER_w_structure("frodo976shake", der, SubjectPublicKeyInfo,
                        frodo976shake),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    DECODER_w_structure("frodo1344aes", der, PrivateKeyInfo, frodo1344aes),
    DECODER_w_structure("frodo1344aes", der, SubjectPublicKeyInfo,
                        frodo1344aes),

#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    DECODER_w_structure("frodo1344shake", der, PrivateKeyInfo, frodo1344shake),
    DECODER_w_structure("frodo1344shake", der, SubjectPublicKeyInfo,
                        frodo1344shake),

#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    DECODER_w_structure("mlkem512", der, PrivateKeyInfo, mlkem512),
    DECODER_w_structure("mlkem512", der, SubjectPublicKeyInfo, mlkem512),

#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    DECODER_w_structure("mlkem768", der, PrivateKeyInfo, mlkem768),
    DECODER_w_structure("mlkem768", der, SubjectPublicKeyInfo, mlkem768),

#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    DECODER_w_structure("mlkem1024", der, PrivateKeyInfo, mlkem1024),
    DECODER_w_structure("mlkem1024", der, SubjectPublicKeyInfo, mlkem1024),

#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    DECODER_w_structure("bikel1", der, PrivateKeyInfo, bikel1),
    DECODER_w_structure("bikel1", der, SubjectPublicKeyInfo, bikel1),

#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    DECODER_w_structure("bikel3", der, PrivateKeyInfo, bikel3),
    DECODER_w_structure("bikel3", der, SubjectPublicKeyInfo, bikel3),

#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    DECODER_w_structure("bikel5", der, PrivateKeyInfo, bikel5),
    DECODER_w_structure("bikel5", der, SubjectPublicKeyInfo, bikel5),

#endif
#ifdef OQS_ENABLE_KEM_hqc_1
    DECODER_w_structure("hqc1", der, PrivateKeyInfo, hqc1),
    DECODER_w_structure("hqc1", der, SubjectPublicKeyInfo, hqc1),

#endif
#ifdef OQS_ENABLE_KEM_hqc_3
    DECODER_w_structure("hqc3", der, PrivateKeyInfo, hqc3),
    DECODER_w_structure("hqc3", der, SubjectPublicKeyInfo, hqc3),

#endif
#ifdef OQS_ENABLE_KEM_hqc_5
    DECODER_w_structure("hqc5", der, PrivateKeyInfo, hqc5),
    DECODER_w_structure("hqc5", der, SubjectPublicKeyInfo, hqc5),

#endif

#endif /* OQS_KEM_ENCODERS */

#ifdef OQS_ENABLE_SIG_ml_dsa_44
    DECODER_w_structure("mldsa44", der, PrivateKeyInfo, mldsa44),
    DECODER_w_structure("mldsa44", der, SubjectPublicKeyInfo, mldsa44),

#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
    DECODER_w_structure("mldsa65", der, PrivateKeyInfo, mldsa65),
    DECODER_w_structure("mldsa65", der, SubjectPublicKeyInfo, mldsa65),

#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
    DECODER_w_structure("mldsa87", der, PrivateKeyInfo, mldsa87),
    DECODER_w_structure("mldsa87", der, SubjectPublicKeyInfo, mldsa87),

#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    DECODER_w_structure("falcon512", der, PrivateKeyInfo, falcon512),
    DECODER_w_structure("falcon512", der, SubjectPublicKeyInfo, falcon512),

#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_512
    DECODER_w_structure("falconpadded512", der, PrivateKeyInfo,
                        falconpadded512),
    DECODER_w_structure("falconpadded512", der, SubjectPublicKeyInfo,
                        falconpadded512),

#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
    DECODER_w_structure("falcon1024", der, PrivateKeyInfo, falcon1024),
    DECODER_w_structure("falcon1024", der, SubjectPublicKeyInfo, falcon1024),

#endif
#ifdef OQS_ENABLE_SIG_falcon_padded_1024
    DECODER_w_structure("falconpadded1024", der, PrivateKeyInfo,
                        falconpadded1024),
    DECODER_w_structure("falconpadded1024", der, SubjectPublicKeyInfo,
                        falconpadded1024),

#endif
#ifdef OQS_ENABLE_SIG_mayo_1
    DECODER_w_structure("mayo1", der, PrivateKeyInfo, mayo1),
    DECODER_w_structure("mayo1", der, SubjectPublicKeyInfo, mayo1),

#endif
#ifdef OQS_ENABLE_SIG_mayo_2
    DECODER_w_structure("mayo2", der, PrivateKeyInfo, mayo2),
    DECODER_w_structure("mayo2", der, SubjectPublicKeyInfo, mayo2),

#endif
#ifdef OQS_ENABLE_SIG_mayo_3
    DECODER_w_structure("mayo3", der, PrivateKeyInfo, mayo3),
    DECODER_w_structure("mayo3", der, SubjectPublicKeyInfo, mayo3),

#endif
#ifdef OQS_ENABLE_SIG_mayo_5
    DECODER_w_structure("mayo5", der, PrivateKeyInfo, mayo5),
    DECODER_w_structure("mayo5", der, SubjectPublicKeyInfo, mayo5),

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

#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Ip_pkc
    DECODER_w_structure("OV_Ip_pkc", der, PrivateKeyInfo, OV_Ip_pkc),
    DECODER_w_structure("OV_Ip_pkc", der, SubjectPublicKeyInfo, OV_Ip_pkc),

#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Is_pkc_skc
    DECODER_w_structure("OV_Is_pkc_skc", der, PrivateKeyInfo, OV_Is_pkc_skc),
    DECODER_w_structure("OV_Is_pkc_skc", der, SubjectPublicKeyInfo,
                        OV_Is_pkc_skc),

#endif
#ifdef OQS_ENABLE_SIG_uov_ov_Ip_pkc_skc
    DECODER_w_structure("OV_Ip_pkc_skc", der, PrivateKeyInfo, OV_Ip_pkc_skc),
    DECODER_w_structure("OV_Ip_pkc_skc", der, SubjectPublicKeyInfo,
                        OV_Ip_pkc_skc),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_K
    DECODER_w_structure("snova1k", der, PrivateKeyInfo, snova1k),
    DECODER_w_structure("snova1k", der, SubjectPublicKeyInfo, snova1k),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_B
    DECODER_w_structure("snova1b", der, PrivateKeyInfo, snova1b),
    DECODER_w_structure("snova1b", der, SubjectPublicKeyInfo, snova1b),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_S
    DECODER_w_structure("snova1s", der, PrivateKeyInfo, snova1s),
    DECODER_w_structure("snova1s", der, SubjectPublicKeyInfo, snova1s),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_K
    DECODER_w_structure("snova3k", der, PrivateKeyInfo, snova3k),
    DECODER_w_structure("snova3k", der, SubjectPublicKeyInfo, snova3k),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_B
    DECODER_w_structure("snova3b", der, PrivateKeyInfo, snova3b),
    DECODER_w_structure("snova3b", der, SubjectPublicKeyInfo, snova3b),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_III_S
    DECODER_w_structure("snova3s", der, PrivateKeyInfo, snova3s),
    DECODER_w_structure("snova3s", der, SubjectPublicKeyInfo, snova3s),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_K
    DECODER_w_structure("snova5k", der, PrivateKeyInfo, snova5k),
    DECODER_w_structure("snova5k", der, SubjectPublicKeyInfo, snova5k),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_B
    DECODER_w_structure("snova5b", der, PrivateKeyInfo, snova5b),
    DECODER_w_structure("snova5b", der, SubjectPublicKeyInfo, snova5b),

#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_V_S
    DECODER_w_structure("snova5s", der, PrivateKeyInfo, snova5s),
    DECODER_w_structure("snova5s", der, SubjectPublicKeyInfo, snova5s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_128s
    DECODER_w_structure("slhdsasha2128s", der, PrivateKeyInfo, slhdsasha2128s),
    DECODER_w_structure("slhdsasha2128s", der, SubjectPublicKeyInfo,
                        slhdsasha2128s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_128f
    DECODER_w_structure("slhdsasha2128f", der, PrivateKeyInfo, slhdsasha2128f),
    DECODER_w_structure("slhdsasha2128f", der, SubjectPublicKeyInfo,
                        slhdsasha2128f),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_192s
    DECODER_w_structure("slhdsasha2192s", der, PrivateKeyInfo, slhdsasha2192s),
    DECODER_w_structure("slhdsasha2192s", der, SubjectPublicKeyInfo,
                        slhdsasha2192s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_192f
    DECODER_w_structure("slhdsasha2192f", der, PrivateKeyInfo, slhdsasha2192f),
    DECODER_w_structure("slhdsasha2192f", der, SubjectPublicKeyInfo,
                        slhdsasha2192f),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_256s
    DECODER_w_structure("slhdsasha2256s", der, PrivateKeyInfo, slhdsasha2256s),
    DECODER_w_structure("slhdsasha2256s", der, SubjectPublicKeyInfo,
                        slhdsasha2256s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_256f
    DECODER_w_structure("slhdsasha2256f", der, PrivateKeyInfo, slhdsasha2256f),
    DECODER_w_structure("slhdsasha2256f", der, SubjectPublicKeyInfo,
                        slhdsasha2256f),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_128s
    DECODER_w_structure("slhdsashake128s", der, PrivateKeyInfo,
                        slhdsashake128s),
    DECODER_w_structure("slhdsashake128s", der, SubjectPublicKeyInfo,
                        slhdsashake128s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_128f
    DECODER_w_structure("slhdsashake128f", der, PrivateKeyInfo,
                        slhdsashake128f),
    DECODER_w_structure("slhdsashake128f", der, SubjectPublicKeyInfo,
                        slhdsashake128f),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_192s
    DECODER_w_structure("slhdsashake192s", der, PrivateKeyInfo,
                        slhdsashake192s),
    DECODER_w_structure("slhdsashake192s", der, SubjectPublicKeyInfo,
                        slhdsashake192s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_192f
    DECODER_w_structure("slhdsashake192f", der, PrivateKeyInfo,
                        slhdsashake192f),
    DECODER_w_structure("slhdsashake192f", der, SubjectPublicKeyInfo,
                        slhdsashake192f),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_256s
    DECODER_w_structure("slhdsashake256s", der, PrivateKeyInfo,
                        slhdsashake256s),
    DECODER_w_structure("slhdsashake256s", der, SubjectPublicKeyInfo,
                        slhdsashake256s),

#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_shake_256f
    DECODER_w_structure("slhdsashake256f", der, PrivateKeyInfo,
                        slhdsashake256f),
    DECODER_w_structure("slhdsashake256f", der, SubjectPublicKeyInfo,
                        slhdsashake256f),

#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat1_gf16_fast_ct
    DECODER_w_structure("mqom3cat1gf16fastct", der, PrivateKeyInfo,
                        mqom3cat1gf16fastct),
    DECODER_w_structure("mqom3cat1gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat1gf16fastct),

#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat3_gf16_fast_ct
    DECODER_w_structure("mqom3cat3gf16fastct", der, PrivateKeyInfo,
                        mqom3cat3gf16fastct),
    DECODER_w_structure("mqom3cat3gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat3gf16fastct),

#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat5_gf16_fast_ct
    DECODER_w_structure("mqom3cat5gf16fastct", der, PrivateKeyInfo,
                        mqom3cat5gf16fastct),
    DECODER_w_structure("mqom3cat5gf16fastct", der, SubjectPublicKeyInfo,
                        mqom3cat5gf16fastct),

#endif
    ///// OQS_TEMPLATE_FRAGMENT_MAKE_END
