Algorithms supported
====================

This page lists all quantum-safe algorithms supported by oqs-provider.

Some algorithms by default may not be enabled for use in the master code-generator template file.

As standardization for these algorithms within TLS is not done, all TLS code points/IDs can be changed from their default values to values set by environment variables. This facilitates interoperability testing with TLS1.3 implementations that use different IDs.

The following list of algorithms may change when loading oqsprovider (version >= 0.9.0) with OpenSSL (version >= 3.5.0); please see [README.md](README.md#using-with-openssl-3.5.0).

# Code points / algorithm IDs

<!--- OQS_TEMPLATE_FRAGMENT_IDS_START -->
|Algorithm name | default ID | enabled | environment variable |
|---------------|:----------:|:-------:|----------------------|
| efrodo640aes | 65024 | Yes | OQS_CODEPOINT_EFRODO640AES |
| efrodo640shake | 65027 | Yes | OQS_CODEPOINT_EFRODO640SHAKE |
| efrodo976aes | 65030 | Yes | OQS_CODEPOINT_EFRODO976AES |
| efrodo976shake | 65033 | Yes | OQS_CODEPOINT_EFRODO976SHAKE |
| efrodo1344aes | 65036 | Yes | OQS_CODEPOINT_EFRODO1344AES |
| efrodo1344shake | 65038 | Yes | OQS_CODEPOINT_EFRODO1344SHAKE |
| frodo640aes | 65059 | Yes | OQS_CODEPOINT_FRODO640AES |
| frodo640shake | 65062 | Yes | OQS_CODEPOINT_FRODO640SHAKE |
| frodo976aes | 65065 | Yes | OQS_CODEPOINT_FRODO976AES |
| frodo976shake | 65068 | Yes | OQS_CODEPOINT_FRODO976SHAKE |
| frodo1344aes | 65071 | Yes | OQS_CODEPOINT_FRODO1344AES |
| frodo1344shake | 65073 | Yes | OQS_CODEPOINT_FRODO1344SHAKE |
| mlkem512 | 512 | Yes | OQS_CODEPOINT_MLKEM512 |
| mlkem768 | 513 | Yes | OQS_CODEPOINT_MLKEM768 |
| mlkem1024 | 514 | Yes | OQS_CODEPOINT_MLKEM1024 |
| bikel1 | 65040 | Yes | OQS_CODEPOINT_BIKEL1 |
| bikel3 | 65043 | Yes | OQS_CODEPOINT_BIKEL3 |
| bikel5 | 65046 | Yes | OQS_CODEPOINT_BIKEL5 |
| hqc1 | 65075 | Yes | OQS_CODEPOINT_HQC1 |
| hqc3 | 65078 | Yes | OQS_CODEPOINT_HQC3 |
| hqc5 | 65081 | Yes | OQS_CODEPOINT_HQC5 |
| mldsa44 | 0x0904 |Yes| OQS_CODEPOINT_MLDSA44
| mldsa65 | 0x0905 |Yes| OQS_CODEPOINT_MLDSA65
| mldsa87 | 0x0906 |Yes| OQS_CODEPOINT_MLDSA87
| falcon512 | 0xfed7 |Yes| OQS_CODEPOINT_FALCON512
| falconpadded512 | 0xfedc |Yes| OQS_CODEPOINT_FALCONPADDED512
| falcon1024 | 0xfeda |Yes| OQS_CODEPOINT_FALCON1024
| falconpadded1024 | 0xfedf |Yes| OQS_CODEPOINT_FALCONPADDED1024
| mayo1 | 0xff7b |Yes| OQS_CODEPOINT_MAYO1
| mayo2 | 0xff7c |Yes| OQS_CODEPOINT_MAYO2
| mayo3 | 0xff7d |Yes| OQS_CODEPOINT_MAYO3
| mayo5 | 0xff7e |Yes| OQS_CODEPOINT_MAYO5
| CROSSrsdp128balanced | 0xff53 |Yes| OQS_CODEPOINT_CROSSRSDP128BALANCED
| CROSSrsdp128fast | 0xff54 |No| OQS_CODEPOINT_CROSSRSDP128FAST
| CROSSrsdp128small | 0xff55 |No| OQS_CODEPOINT_CROSSRSDP128SMALL
| CROSSrsdp192balanced | 0xff56 |No| OQS_CODEPOINT_CROSSRSDP192BALANCED
| CROSSrsdp192fast | 0xff57 |No| OQS_CODEPOINT_CROSSRSDP192FAST
| CROSSrsdp192small | 0xff58 |No| OQS_CODEPOINT_CROSSRSDP192SMALL
| CROSSrsdp256small | 0xff59 |No| OQS_CODEPOINT_CROSSRSDP256SMALL
| CROSSrsdpg128balanced | 0xff5a |No| OQS_CODEPOINT_CROSSRSDPG128BALANCED
| CROSSrsdpg128fast | 0xff5b |No| OQS_CODEPOINT_CROSSRSDPG128FAST
| CROSSrsdpg128small | 0xff5c |No| OQS_CODEPOINT_CROSSRSDPG128SMALL
| CROSSrsdpg192balanced | 0xff5d |No| OQS_CODEPOINT_CROSSRSDPG192BALANCED
| CROSSrsdpg192fast | 0xff5e |No| OQS_CODEPOINT_CROSSRSDPG192FAST
| CROSSrsdpg192small | 0xff5f |No| OQS_CODEPOINT_CROSSRSDPG192SMALL
| CROSSrsdpg256balanced | 0xff60 |No| OQS_CODEPOINT_CROSSRSDPG256BALANCED
| CROSSrsdpg256fast | 0xff61 |No| OQS_CODEPOINT_CROSSRSDPG256FAST
| CROSSrsdpg256small | 0xff62 |No| OQS_CODEPOINT_CROSSRSDPG256SMALL
| OV_Is | 0xff0a |No| OQS_CODEPOINT_OV_IS
| OV_Ip | 0xff0b |No| OQS_CODEPOINT_OV_IP
| OV_III | 0xff0c |No| OQS_CODEPOINT_OV_III
| OV_V | 0xff0d |No| OQS_CODEPOINT_OV_V
| OV_Is_pkc | 0xff0e |Yes| OQS_CODEPOINT_OV_IS_PKC
| OV_Ip_pkc | 0xff0f |Yes| OQS_CODEPOINT_OV_IP_PKC
| OV_III_pkc | 0xff10 |No| OQS_CODEPOINT_OV_III_PKC
| OV_V_pkc | 0xff11 |No| OQS_CODEPOINT_OV_V_PKC
| OV_Is_pkc_skc | 0xff12 |Yes| OQS_CODEPOINT_OV_IS_PKC_SKC
| OV_Ip_pkc_skc | 0xff13 |Yes| OQS_CODEPOINT_OV_IP_PKC_SKC
| OV_III_pkc_skc | 0xff14 |No| OQS_CODEPOINT_OV_III_PKC_SKC
| OV_V_pkc_skc | 0xff15 |No| OQS_CODEPOINT_OV_V_PKC_SKC
| snova1k | 0xff83 |Yes| OQS_CODEPOINT_SNOVA1K
| snova1b | 0xff85 |Yes| OQS_CODEPOINT_SNOVA1B
| snova1s | 0xff87 |Yes| OQS_CODEPOINT_SNOVA1S
| snova3k | 0xff89 |Yes| OQS_CODEPOINT_SNOVA3K
| snova3b | 0xff8b |Yes| OQS_CODEPOINT_SNOVA3B
| snova3s | 0xff8d |Yes| OQS_CODEPOINT_SNOVA3S
| snova5k | 0xff8f |Yes| OQS_CODEPOINT_SNOVA5K
| snova5b | 0xff91 |Yes| OQS_CODEPOINT_SNOVA5B
| snova5s | 0xff93 |Yes| OQS_CODEPOINT_SNOVA5S
| slhdsasha2128s | 0x0911 |Yes| OQS_CODEPOINT_SLHDSASHA2128S
| slhdsasha2128f | 0x0912 |Yes| OQS_CODEPOINT_SLHDSASHA2128F
| slhdsasha2192s | 0x0913 |Yes| OQS_CODEPOINT_SLHDSASHA2192S
| slhdsasha2192f | 0x0914 |Yes| OQS_CODEPOINT_SLHDSASHA2192F
| slhdsasha2256s | 0x0915 |Yes| OQS_CODEPOINT_SLHDSASHA2256S
| slhdsasha2256f | 0x0916 |Yes| OQS_CODEPOINT_SLHDSASHA2256F
| slhdsashake128s | 0x0917 |Yes| OQS_CODEPOINT_SLHDSASHAKE128S
| slhdsashake128f | 0x0918 |Yes| OQS_CODEPOINT_SLHDSASHAKE128F
| slhdsashake192s | 0x0919 |Yes| OQS_CODEPOINT_SLHDSASHAKE192S
| slhdsashake192f | 0x091A |Yes| OQS_CODEPOINT_SLHDSASHAKE192F
| slhdsashake256s | 0x091B |Yes| OQS_CODEPOINT_SLHDSASHAKE256S
| slhdsashake256f | 0x091C |Yes| OQS_CODEPOINT_SLHDSASHAKE256F
| mqom3cat1gf16fastct | 0xff99 |Yes| OQS_CODEPOINT_MQOM3CAT1GF16FASTCT
| mqom3cat1gf16fastot | 0xff9b |No| OQS_CODEPOINT_MQOM3CAT1GF16FASTOT
| mqom3cat1gf16shortct | 0xff9d |No| OQS_CODEPOINT_MQOM3CAT1GF16SHORTCT
| mqom3cat1gf16shortot | 0xff9f |No| OQS_CODEPOINT_MQOM3CAT1GF16SHORTOT
| mqom3cat1gf2shorterct | 0xffa1 |No| OQS_CODEPOINT_MQOM3CAT1GF2SHORTERCT
| mqom3cat1gf2shorterot | 0xffa3 |No| OQS_CODEPOINT_MQOM3CAT1GF2SHORTEROT
| mqom3cat3gf16fastct | 0xffa5 |Yes| OQS_CODEPOINT_MQOM3CAT3GF16FASTCT
| mqom3cat3gf16fastot | 0xffa7 |No| OQS_CODEPOINT_MQOM3CAT3GF16FASTOT
| mqom3cat3gf16shortct | 0xffa9 |No| OQS_CODEPOINT_MQOM3CAT3GF16SHORTCT
| mqom3cat3gf16shortot | 0xffab |No| OQS_CODEPOINT_MQOM3CAT3GF16SHORTOT
| mqom3cat3gf2shorterct | 0xffad |No| OQS_CODEPOINT_MQOM3CAT3GF2SHORTERCT
| mqom3cat3gf2shorterot | 0xffaf |No| OQS_CODEPOINT_MQOM3CAT3GF2SHORTEROT
| mqom3cat5gf16fastct | 0xffb1 |Yes| OQS_CODEPOINT_MQOM3CAT5GF16FASTCT
| mqom3cat5gf16fastot | 0xffb3 |No| OQS_CODEPOINT_MQOM3CAT5GF16FASTOT
| mqom3cat5gf16shortct | 0xffb5 |No| OQS_CODEPOINT_MQOM3CAT5GF16SHORTCT
| mqom3cat5gf16shortot | 0xffb7 |No| OQS_CODEPOINT_MQOM3CAT5GF16SHORTOT
| mqom3cat5gf2shorterct | 0xffb9 |No| OQS_CODEPOINT_MQOM3CAT5GF2SHORTERCT
| mqom3cat5gf2shorterot | 0xffbb |No| OQS_CODEPOINT_MQOM3CAT5GF2SHORTEROT
<!--- OQS_TEMPLATE_FRAGMENT_IDS_END -->

Changing code points
--------------------

In order to dynamically change the code point of any one algorithm, the respective
environment variable listed above has to be set to the `INT`eger value of the
desired code point. For example, as Cloudflare has chosen `0xfe30` as the code
point for their hybrid X25519_kyber512 implementation, the following command
can be used to successfully confirm interoperability between the oqs-provider
and the Cloudflare infrastructure using this hybrid classic/quantum-safe algorithm:

```
OQS_CODEPOINT_X25519_KYBER512=65072  ./openssl/apps/openssl s_client -groups x25519_kyber512 -connect cloudflare.com:443 -provider-path _build/oqsprov -provider oqsprovider -provider default
```

# OIDs

Along the same lines as the code points, X.509 OIDs may be subject to change
prior to final standardization. The environment variables below permit
adapting the OIDs of all supported signature algorithms as per the table below.
OIDs denoted with NULL are not maintained and may lead to errors in code
execution. Anyone interested in using an algorithm with such designation is
requested to contribute to the maintenance of these OIDs along the lines
discussed in https://github.com/open-quantum-safe/oqs-provider/issues/351.

<!--- OQS_TEMPLATE_FRAGMENT_OIDS_START -->
|Algorithm name |    default OID    | enabled | environment variable |
|---------------|:-----------------:|:-------:|----------------------|
| mldsa44 | 2.16.840.1.101.3.4.3.17 |Yes| OQS_OID_MLDSA44
| mldsa65 | 2.16.840.1.101.3.4.3.18 |Yes| OQS_OID_MLDSA65
| mldsa87 | 2.16.840.1.101.3.4.3.19 |Yes| OQS_OID_MLDSA87
| falcon512 | 1.3.9999.3.11 |Yes| OQS_OID_FALCON512
| falconpadded512 | 1.3.9999.3.16 |Yes| OQS_OID_FALCONPADDED512
| falcon1024 | 1.3.9999.3.14 |Yes| OQS_OID_FALCON1024
| falconpadded1024 | 1.3.9999.3.19 |Yes| OQS_OID_FALCONPADDED1024
| mayo1 | 1.3.9999.8.1.5 |Yes| OQS_OID_MAYO1
| mayo2 | 1.3.9999.8.2.5 |Yes| OQS_OID_MAYO2
| mayo3 | 1.3.9999.8.3.5 |Yes| OQS_OID_MAYO3
| mayo5 | 1.3.9999.8.5.5 |Yes| OQS_OID_MAYO5
| CROSSrsdp128balanced | 1.3.6.1.4.1.62245.2.1.1.2.2 |Yes| OQS_OID_CROSSRSDP128BALANCED
| CROSSrsdp128fast | 1.3.6.1.4.1.62245.2.1.2.2.2 |No| OQS_OID_CROSSRSDP128FAST
| CROSSrsdp128small | 1.3.6.1.4.1.62245.2.1.3.2.2 |No| OQS_OID_CROSSRSDP128SMALL
| CROSSrsdp192balanced | 1.3.6.1.4.1.62245.2.1.4.2.2 |No| OQS_OID_CROSSRSDP192BALANCED
| CROSSrsdp192fast | 1.3.6.1.4.1.62245.2.1.5.2.2 |No| OQS_OID_CROSSRSDP192FAST
| CROSSrsdp192small | 1.3.6.1.4.1.62245.2.1.6.2.2 |No| OQS_OID_CROSSRSDP192SMALL
| CROSSrsdp256small | 1.3.6.1.4.1.62245.2.1.9.2.2 |No| OQS_OID_CROSSRSDP256SMALL
| CROSSrsdpg128balanced | 1.3.6.1.4.1.62245.2.1.10.2.2 |No| OQS_OID_CROSSRSDPG128BALANCED
| CROSSrsdpg128fast | 1.3.6.1.4.1.62245.2.1.11.2.2 |No| OQS_OID_CROSSRSDPG128FAST
| CROSSrsdpg128small | 1.3.6.1.4.1.62245.2.1.12.2.2 |No| OQS_OID_CROSSRSDPG128SMALL
| CROSSrsdpg192balanced | 1.3.6.1.4.1.62245.2.1.13.2.2 |No| OQS_OID_CROSSRSDPG192BALANCED
| CROSSrsdpg192fast | 1.3.6.1.4.1.62245.2.1.14.2.2 |No| OQS_OID_CROSSRSDPG192FAST
| CROSSrsdpg192small | 1.3.6.1.4.1.62245.2.1.15.2.2 |No| OQS_OID_CROSSRSDPG192SMALL
| CROSSrsdpg256balanced | 1.3.6.1.4.1.62245.2.1.16.2.2 |No| OQS_OID_CROSSRSDPG256BALANCED
| CROSSrsdpg256fast | 1.3.6.1.4.1.62245.2.1.17.2.2 |No| OQS_OID_CROSSRSDPG256FAST
| CROSSrsdpg256small | 1.3.6.1.4.1.62245.2.1.18.2.2 |No| OQS_OID_CROSSRSDPG256SMALL
| OV_Is | 1.3.9999.9.1.1 |No| OQS_OID_OV_IS
| OV_Ip | 1.3.9999.9.2.1 |No| OQS_OID_OV_IP
| OV_III | 1.3.9999.9.3.1 |No| OQS_OID_OV_III
| OV_V | 1.3.9999.9.4.1 |No| OQS_OID_OV_V
| OV_Is_pkc | 1.3.9999.9.5.1 |Yes| OQS_OID_OV_IS_PKC
| OV_Ip_pkc | 1.3.9999.9.6.1 |Yes| OQS_OID_OV_IP_PKC
| OV_III_pkc | 1.3.9999.9.7.1 |No| OQS_OID_OV_III_PKC
| OV_V_pkc | 1.3.9999.9.8.1 |No| OQS_OID_OV_V_PKC
| OV_Is_pkc_skc | 1.3.9999.9.9.1 |Yes| OQS_OID_OV_IS_PKC_SKC
| OV_Ip_pkc_skc | 1.3.9999.9.10.1 |Yes| OQS_OID_OV_IP_PKC_SKC
| OV_III_pkc_skc | 1.3.9999.9.11.1 |No| OQS_OID_OV_III_PKC_SKC
| OV_V_pkc_skc | 1.3.9999.9.12.1 |No| OQS_OID_OV_V_PKC_SKC
| snova1k | 1.3.9999.10.1.3 |Yes| OQS_OID_SNOVA1K
| snova1b | 1.3.9999.10.2.3 |Yes| OQS_OID_SNOVA1B
| snova1s | 1.3.9999.10.3.3 |Yes| OQS_OID_SNOVA1S
| snova3k | 1.3.9999.10.4.3 |Yes| OQS_OID_SNOVA3K
| snova3b | 1.3.9999.10.5.3 |Yes| OQS_OID_SNOVA3B
| snova3s | 1.3.9999.10.6.3 |Yes| OQS_OID_SNOVA3S
| snova5k | 1.3.9999.10.7.3 |Yes| OQS_OID_SNOVA5K
| snova5b | 1.3.9999.10.8.3 |Yes| OQS_OID_SNOVA5B
| snova5s | 1.3.9999.10.9.3 |Yes| OQS_OID_SNOVA5S
| slhdsasha2128s | 2.16.840.1.101.3.4.3.20 |Yes| OQS_OID_SLHDSASHA2128S
| slhdsasha2128f | 2.16.840.1.101.3.4.3.21 |Yes| OQS_OID_SLHDSASHA2128F
| slhdsasha2192s | 2.16.840.1.101.3.4.3.22 |Yes| OQS_OID_SLHDSASHA2192S
| slhdsasha2192f | 2.16.840.1.101.3.4.3.23 |Yes| OQS_OID_SLHDSASHA2192F
| slhdsasha2256s | 2.16.840.1.101.3.4.3.24 |Yes| OQS_OID_SLHDSASHA2256S
| slhdsasha2256f | 2.16.840.1.101.3.4.3.25 |Yes| OQS_OID_SLHDSASHA2256F
| slhdsashake128s | 2.16.840.1.101.3.4.3.26 |Yes| OQS_OID_SLHDSASHAKE128S
| slhdsashake128f | 2.16.840.1.101.3.4.3.27 |Yes| OQS_OID_SLHDSASHAKE128F
| slhdsashake192s | 2.16.840.1.101.3.4.3.28 |Yes| OQS_OID_SLHDSASHAKE192S
| slhdsashake192f | 2.16.840.1.101.3.4.3.29 |Yes| OQS_OID_SLHDSASHAKE192F
| slhdsashake256s | 2.16.840.1.101.3.4.3.30 |Yes| OQS_OID_SLHDSASHAKE256S
| slhdsashake256f | 2.16.840.1.101.3.4.3.31 |Yes| OQS_OID_SLHDSASHAKE256F
| mqom3cat1gf16fastct | 1.3.9999.11.1.9 |Yes| OQS_OID_MQOM3CAT1GF16FASTCT
| mqom3cat1gf16fastot | 1.3.9999.11.1.11 |No| OQS_OID_MQOM3CAT1GF16FASTOT
| mqom3cat1gf16shortct | 1.3.9999.11.1.13 |No| OQS_OID_MQOM3CAT1GF16SHORTCT
| mqom3cat1gf16shortot | 1.3.9999.11.1.15 |No| OQS_OID_MQOM3CAT1GF16SHORTOT
| mqom3cat1gf2shorterct | 1.3.9999.11.1.17 |No| OQS_OID_MQOM3CAT1GF2SHORTERCT
| mqom3cat1gf2shorterot | 1.3.9999.11.1.19 |No| OQS_OID_MQOM3CAT1GF2SHORTEROT
| mqom3cat3gf16fastct | 1.3.9999.11.3.9 |Yes| OQS_OID_MQOM3CAT3GF16FASTCT
| mqom3cat3gf16fastot | 1.3.9999.11.3.11 |No| OQS_OID_MQOM3CAT3GF16FASTOT
| mqom3cat3gf16shortct | 1.3.9999.11.3.13 |No| OQS_OID_MQOM3CAT3GF16SHORTCT
| mqom3cat3gf16shortot | 1.3.9999.11.3.15 |No| OQS_OID_MQOM3CAT3GF16SHORTOT
| mqom3cat3gf2shorterct | 1.3.9999.11.3.17 |No| OQS_OID_MQOM3CAT3GF2SHORTERCT
| mqom3cat3gf2shorterot | 1.3.9999.11.3.19 |No| OQS_OID_MQOM3CAT3GF2SHORTEROT
| mqom3cat5gf16fastct | 1.3.9999.11.5.9 |Yes| OQS_OID_MQOM3CAT5GF16FASTCT
| mqom3cat5gf16fastot | 1.3.9999.11.5.11 |No| OQS_OID_MQOM3CAT5GF16FASTOT
| mqom3cat5gf16shortct | 1.3.9999.11.5.13 |No| OQS_OID_MQOM3CAT5GF16SHORTCT
| mqom3cat5gf16shortot | 1.3.9999.11.5.15 |No| OQS_OID_MQOM3CAT5GF16SHORTOT
| mqom3cat5gf2shorterct | 1.3.9999.11.5.17 |No| OQS_OID_MQOM3CAT5GF2SHORTERCT
| mqom3cat5gf2shorterot | 1.3.9999.11.5.19 |No| OQS_OID_MQOM3CAT5GF2SHORTEROT

If [OQS_KEM_ENCODERS](CONFIGURE.md#OQS_KEM_ENCODERS) is enabled the following list is also available:

|Algorithm name |    default OID    | environment variable |
|---------------|:-----------------:|----------------------|
| efrodo640aes | NULL | OQS_OID_EFRODO640AES
| efrodo640shake | NULL | OQS_OID_EFRODO640SHAKE
| efrodo976aes | NULL | OQS_OID_EFRODO976AES
| efrodo976shake | NULL | OQS_OID_EFRODO976SHAKE
| efrodo1344aes | NULL | OQS_OID_EFRODO1344AES
| efrodo1344shake | NULL | OQS_OID_EFRODO1344SHAKE
| frodo640aes | NULL | OQS_OID_FRODO640AES
| frodo640shake | NULL | OQS_OID_FRODO640SHAKE
| frodo976aes | NULL | OQS_OID_FRODO976AES
| frodo976shake | NULL | OQS_OID_FRODO976SHAKE
| frodo1344aes | NULL | OQS_OID_FRODO1344AES
| frodo1344shake | NULL | OQS_OID_FRODO1344SHAKE
| mlkem512 | 2.16.840.1.101.3.4.4.1 | OQS_OID_MLKEM512
| mlkem768 | 2.16.840.1.101.3.4.4.2 | OQS_OID_MLKEM768
| mlkem1024 | 2.16.840.1.101.3.4.4.3 | OQS_OID_MLKEM1024
| bikel1 | NULL | OQS_OID_BIKEL1
| bikel3 | NULL | OQS_OID_BIKEL3
| bikel5 | NULL | OQS_OID_BIKEL5
| hqc1 | NULL | OQS_OID_HQC1
| hqc3 | NULL | OQS_OID_HQC3
| hqc5 | NULL | OQS_OID_HQC5
<!--- OQS_TEMPLATE_FRAGMENT_OIDS_END -->

