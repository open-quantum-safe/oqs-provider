// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider decoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef DECODER_PROVIDER
# error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair         "type-specific"
#define DECODER_STRUCTURE_type_specific_params          "type-specific"
#define DECODER_STRUCTURE_type_specific                 "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub          "type-specific"
#define DECODER_STRUCTURE_PKCS8                         "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo          "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo                "PrivateKeyInfo"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                          \
    { _name,                                                            \
      "provider=" DECODER_PROVIDER ",input=" #_input,   \
      (oqs_##_input##_to_##_output##_decoder_functions) }
#define DECODER_w_structure(_name, _input, _structure, _output)  \
    { _name,                                                            \
      "provider=" DECODER_PROVIDER ",input=" #_input    \
      ",structure=" DECODER_STRUCTURE_##_structure,                     \
      (oqs_##_structure##_##_input##_to_##_output##_decoder_functions) }

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
DECODER_w_structure("dilithium2", der, PrivateKeyInfo, dilithium2),
DECODER_w_structure("dilithium2", der, SubjectPublicKeyInfo, dilithium2),DECODER_w_structure("p256_dilithium2", der, PrivateKeyInfo, p256_dilithium2),
DECODER_w_structure("p256_dilithium2", der, SubjectPublicKeyInfo, p256_dilithium2),DECODER_w_structure("rsa3072_dilithium2", der, PrivateKeyInfo, rsa3072_dilithium2),
DECODER_w_structure("rsa3072_dilithium2", der, SubjectPublicKeyInfo, rsa3072_dilithium2),
DECODER_w_structure("dilithium3", der, PrivateKeyInfo, dilithium3),
DECODER_w_structure("dilithium3", der, SubjectPublicKeyInfo, dilithium3),DECODER_w_structure("p384_dilithium3", der, PrivateKeyInfo, p384_dilithium3),
DECODER_w_structure("p384_dilithium3", der, SubjectPublicKeyInfo, p384_dilithium3),
DECODER_w_structure("dilithium5", der, PrivateKeyInfo, dilithium5),
DECODER_w_structure("dilithium5", der, SubjectPublicKeyInfo, dilithium5),DECODER_w_structure("p521_dilithium5", der, PrivateKeyInfo, p521_dilithium5),
DECODER_w_structure("p521_dilithium5", der, SubjectPublicKeyInfo, p521_dilithium5),
DECODER_w_structure("dilithium2_aes", der, PrivateKeyInfo, dilithium2_aes),
DECODER_w_structure("dilithium2_aes", der, SubjectPublicKeyInfo, dilithium2_aes),DECODER_w_structure("p256_dilithium2_aes", der, PrivateKeyInfo, p256_dilithium2_aes),
DECODER_w_structure("p256_dilithium2_aes", der, SubjectPublicKeyInfo, p256_dilithium2_aes),DECODER_w_structure("rsa3072_dilithium2_aes", der, PrivateKeyInfo, rsa3072_dilithium2_aes),
DECODER_w_structure("rsa3072_dilithium2_aes", der, SubjectPublicKeyInfo, rsa3072_dilithium2_aes),
DECODER_w_structure("dilithium3_aes", der, PrivateKeyInfo, dilithium3_aes),
DECODER_w_structure("dilithium3_aes", der, SubjectPublicKeyInfo, dilithium3_aes),DECODER_w_structure("p384_dilithium3_aes", der, PrivateKeyInfo, p384_dilithium3_aes),
DECODER_w_structure("p384_dilithium3_aes", der, SubjectPublicKeyInfo, p384_dilithium3_aes),
DECODER_w_structure("dilithium5_aes", der, PrivateKeyInfo, dilithium5_aes),
DECODER_w_structure("dilithium5_aes", der, SubjectPublicKeyInfo, dilithium5_aes),DECODER_w_structure("p521_dilithium5_aes", der, PrivateKeyInfo, p521_dilithium5_aes),
DECODER_w_structure("p521_dilithium5_aes", der, SubjectPublicKeyInfo, p521_dilithium5_aes),
DECODER_w_structure("falcon512", der, PrivateKeyInfo, falcon512),
DECODER_w_structure("falcon512", der, SubjectPublicKeyInfo, falcon512),DECODER_w_structure("p256_falcon512", der, PrivateKeyInfo, p256_falcon512),
DECODER_w_structure("p256_falcon512", der, SubjectPublicKeyInfo, p256_falcon512),DECODER_w_structure("rsa3072_falcon512", der, PrivateKeyInfo, rsa3072_falcon512),
DECODER_w_structure("rsa3072_falcon512", der, SubjectPublicKeyInfo, rsa3072_falcon512),
DECODER_w_structure("falcon1024", der, PrivateKeyInfo, falcon1024),
DECODER_w_structure("falcon1024", der, SubjectPublicKeyInfo, falcon1024),DECODER_w_structure("p521_falcon1024", der, PrivateKeyInfo, p521_falcon1024),
DECODER_w_structure("p521_falcon1024", der, SubjectPublicKeyInfo, p521_falcon1024),
DECODER_w_structure("picnicl1full", der, PrivateKeyInfo, picnicl1full),
DECODER_w_structure("picnicl1full", der, SubjectPublicKeyInfo, picnicl1full),DECODER_w_structure("p256_picnicl1full", der, PrivateKeyInfo, p256_picnicl1full),
DECODER_w_structure("p256_picnicl1full", der, SubjectPublicKeyInfo, p256_picnicl1full),DECODER_w_structure("rsa3072_picnicl1full", der, PrivateKeyInfo, rsa3072_picnicl1full),
DECODER_w_structure("rsa3072_picnicl1full", der, SubjectPublicKeyInfo, rsa3072_picnicl1full),
DECODER_w_structure("picnic3l1", der, PrivateKeyInfo, picnic3l1),
DECODER_w_structure("picnic3l1", der, SubjectPublicKeyInfo, picnic3l1),DECODER_w_structure("p256_picnic3l1", der, PrivateKeyInfo, p256_picnic3l1),
DECODER_w_structure("p256_picnic3l1", der, SubjectPublicKeyInfo, p256_picnic3l1),DECODER_w_structure("rsa3072_picnic3l1", der, PrivateKeyInfo, rsa3072_picnic3l1),
DECODER_w_structure("rsa3072_picnic3l1", der, SubjectPublicKeyInfo, rsa3072_picnic3l1),
DECODER_w_structure("rainbowVclassic", der, PrivateKeyInfo, rainbowVclassic),
DECODER_w_structure("rainbowVclassic", der, SubjectPublicKeyInfo, rainbowVclassic),DECODER_w_structure("p521_rainbowVclassic", der, PrivateKeyInfo, p521_rainbowVclassic),
DECODER_w_structure("p521_rainbowVclassic", der, SubjectPublicKeyInfo, p521_rainbowVclassic),
DECODER_w_structure("sphincsharaka128frobust", der, PrivateKeyInfo, sphincsharaka128frobust),
DECODER_w_structure("sphincsharaka128frobust", der, SubjectPublicKeyInfo, sphincsharaka128frobust),DECODER_w_structure("p256_sphincsharaka128frobust", der, PrivateKeyInfo, p256_sphincsharaka128frobust),
DECODER_w_structure("p256_sphincsharaka128frobust", der, SubjectPublicKeyInfo, p256_sphincsharaka128frobust),DECODER_w_structure("rsa3072_sphincsharaka128frobust", der, PrivateKeyInfo, rsa3072_sphincsharaka128frobust),
DECODER_w_structure("rsa3072_sphincsharaka128frobust", der, SubjectPublicKeyInfo, rsa3072_sphincsharaka128frobust),
DECODER_w_structure("sphincssha256128frobust", der, PrivateKeyInfo, sphincssha256128frobust),
DECODER_w_structure("sphincssha256128frobust", der, SubjectPublicKeyInfo, sphincssha256128frobust),DECODER_w_structure("p256_sphincssha256128frobust", der, PrivateKeyInfo, p256_sphincssha256128frobust),
DECODER_w_structure("p256_sphincssha256128frobust", der, SubjectPublicKeyInfo, p256_sphincssha256128frobust),DECODER_w_structure("rsa3072_sphincssha256128frobust", der, PrivateKeyInfo, rsa3072_sphincssha256128frobust),
DECODER_w_structure("rsa3072_sphincssha256128frobust", der, SubjectPublicKeyInfo, rsa3072_sphincssha256128frobust),
DECODER_w_structure("sphincsshake256128frobust", der, PrivateKeyInfo, sphincsshake256128frobust),
DECODER_w_structure("sphincsshake256128frobust", der, SubjectPublicKeyInfo, sphincsshake256128frobust),DECODER_w_structure("p256_sphincsshake256128frobust", der, PrivateKeyInfo, p256_sphincsshake256128frobust),
DECODER_w_structure("p256_sphincsshake256128frobust", der, SubjectPublicKeyInfo, p256_sphincsshake256128frobust),DECODER_w_structure("rsa3072_sphincsshake256128frobust", der, PrivateKeyInfo, rsa3072_sphincsshake256128frobust),
DECODER_w_structure("rsa3072_sphincsshake256128frobust", der, SubjectPublicKeyInfo, rsa3072_sphincsshake256128frobust),
///// OQS_TEMPLATE_FRAGMENT_MAKE_END
