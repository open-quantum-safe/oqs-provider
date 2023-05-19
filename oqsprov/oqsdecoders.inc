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
#ifdef OQS_ENABLE_SIG_dilithium_2
DECODER_w_structure("dilithium2", der, PrivateKeyInfo, dilithium2),
DECODER_w_structure("dilithium2", der, SubjectPublicKeyInfo, dilithium2),DECODER_w_structure("p256_dilithium2", der, PrivateKeyInfo, p256_dilithium2),
DECODER_w_structure("p256_dilithium2", der, SubjectPublicKeyInfo, p256_dilithium2),DECODER_w_structure("rsa3072_dilithium2", der, PrivateKeyInfo, rsa3072_dilithium2),
DECODER_w_structure("rsa3072_dilithium2", der, SubjectPublicKeyInfo, rsa3072_dilithium2),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
DECODER_w_structure("dilithium3", der, PrivateKeyInfo, dilithium3),
DECODER_w_structure("dilithium3", der, SubjectPublicKeyInfo, dilithium3),DECODER_w_structure("p384_dilithium3", der, PrivateKeyInfo, p384_dilithium3),
DECODER_w_structure("p384_dilithium3", der, SubjectPublicKeyInfo, p384_dilithium3),
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
DECODER_w_structure("dilithium5", der, PrivateKeyInfo, dilithium5),
DECODER_w_structure("dilithium5", der, SubjectPublicKeyInfo, dilithium5),DECODER_w_structure("p521_dilithium5", der, PrivateKeyInfo, p521_dilithium5),
DECODER_w_structure("p521_dilithium5", der, SubjectPublicKeyInfo, p521_dilithium5),
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
DECODER_w_structure("falcon512", der, PrivateKeyInfo, falcon512),
DECODER_w_structure("falcon512", der, SubjectPublicKeyInfo, falcon512),DECODER_w_structure("p256_falcon512", der, PrivateKeyInfo, p256_falcon512),
DECODER_w_structure("p256_falcon512", der, SubjectPublicKeyInfo, p256_falcon512),DECODER_w_structure("rsa3072_falcon512", der, PrivateKeyInfo, rsa3072_falcon512),
DECODER_w_structure("rsa3072_falcon512", der, SubjectPublicKeyInfo, rsa3072_falcon512),
#endif
#ifdef OQS_ENABLE_SIG_falcon_1024
DECODER_w_structure("falcon1024", der, PrivateKeyInfo, falcon1024),
DECODER_w_structure("falcon1024", der, SubjectPublicKeyInfo, falcon1024),DECODER_w_structure("p521_falcon1024", der, PrivateKeyInfo, p521_falcon1024),
DECODER_w_structure("p521_falcon1024", der, SubjectPublicKeyInfo, p521_falcon1024),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128f_simple
DECODER_w_structure("sphincssha2128fsimple", der, PrivateKeyInfo, sphincssha2128fsimple),
DECODER_w_structure("sphincssha2128fsimple", der, SubjectPublicKeyInfo, sphincssha2128fsimple),DECODER_w_structure("p256_sphincssha2128fsimple", der, PrivateKeyInfo, p256_sphincssha2128fsimple),
DECODER_w_structure("p256_sphincssha2128fsimple", der, SubjectPublicKeyInfo, p256_sphincssha2128fsimple),DECODER_w_structure("rsa3072_sphincssha2128fsimple", der, PrivateKeyInfo, rsa3072_sphincssha2128fsimple),
DECODER_w_structure("rsa3072_sphincssha2128fsimple", der, SubjectPublicKeyInfo, rsa3072_sphincssha2128fsimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_128s_simple
DECODER_w_structure("sphincssha2128ssimple", der, PrivateKeyInfo, sphincssha2128ssimple),
DECODER_w_structure("sphincssha2128ssimple", der, SubjectPublicKeyInfo, sphincssha2128ssimple),DECODER_w_structure("p256_sphincssha2128ssimple", der, PrivateKeyInfo, p256_sphincssha2128ssimple),
DECODER_w_structure("p256_sphincssha2128ssimple", der, SubjectPublicKeyInfo, p256_sphincssha2128ssimple),DECODER_w_structure("rsa3072_sphincssha2128ssimple", der, PrivateKeyInfo, rsa3072_sphincssha2128ssimple),
DECODER_w_structure("rsa3072_sphincssha2128ssimple", der, SubjectPublicKeyInfo, rsa3072_sphincssha2128ssimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_sha2_192f_simple
DECODER_w_structure("sphincssha2192fsimple", der, PrivateKeyInfo, sphincssha2192fsimple),
DECODER_w_structure("sphincssha2192fsimple", der, SubjectPublicKeyInfo, sphincssha2192fsimple),DECODER_w_structure("p384_sphincssha2192fsimple", der, PrivateKeyInfo, p384_sphincssha2192fsimple),
DECODER_w_structure("p384_sphincssha2192fsimple", der, SubjectPublicKeyInfo, p384_sphincssha2192fsimple),
#endif
#ifdef OQS_ENABLE_SIG_sphincs_shake_128f_simple
DECODER_w_structure("sphincsshake128fsimple", der, PrivateKeyInfo, sphincsshake128fsimple),
DECODER_w_structure("sphincsshake128fsimple", der, SubjectPublicKeyInfo, sphincsshake128fsimple),DECODER_w_structure("p256_sphincsshake128fsimple", der, PrivateKeyInfo, p256_sphincsshake128fsimple),
DECODER_w_structure("p256_sphincsshake128fsimple", der, SubjectPublicKeyInfo, p256_sphincsshake128fsimple),DECODER_w_structure("rsa3072_sphincsshake128fsimple", der, PrivateKeyInfo, rsa3072_sphincsshake128fsimple),
DECODER_w_structure("rsa3072_sphincsshake128fsimple", der, SubjectPublicKeyInfo, rsa3072_sphincsshake128fsimple),
#endif
///// OQS_TEMPLATE_FRAGMENT_MAKE_END
