// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/evp.h>
#include <openssl/provider.h>
#include "test_common.h"
#include <string.h>

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

#define ECP_NAME(secbits, oqsname) \
    (secbits == 128 ? "p256_" #oqsname "" : \
     secbits == 192 ? "p384_" #oqsname "" : \
                      "p521_" #oqsname "")
#define ECX_NAME(secbits, oqsname) \
    (secbits == 128 ? "x25519_" #oqsname "" : \
                        "x448_" #oqsname "")

#define KEMALG3(NAMES, SECBITS) \
  "" #NAMES "", ECP_NAME(SECBITS, NAMES), ECX_NAME(SECBITS, NAMES)
#define KEMALG2(NAMES, SECBITS) \
  "" #NAMES "", ECP_NAME(SECBITS, NAMES)

static const char *kemalg_names[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_CASES_START
    KEMALG3(frodo640aes, 128),
    KEMALG3(frodo640shake, 128),
    KEMALG3(frodo976aes, 192),
    KEMALG3(frodo976shake, 192),
    KEMALG2(frodo1344aes, 256),
    KEMALG2(frodo1344shake, 256),
    KEMALG3(kyber512, 128),
    KEMALG3(kyber768, 192),
    KEMALG2(kyber1024, 256),
    KEMALG3(ntru_hps2048509, 128),
    KEMALG3(ntru_hps2048677, 192),
    KEMALG2(ntru_hps4096821, 256),
    KEMALG2(ntru_hps40961229, 256),
    KEMALG3(ntru_hrss701, 192),
    KEMALG2(ntru_hrss1373, 256),
    KEMALG3(lightsaber, 128),
    KEMALG3(saber, 192),
    KEMALG2(firesaber, 256),
    KEMALG3(bikel1, 128),
    KEMALG3(bikel3, 192),
    KEMALG3(kyber90s512, 128),
    KEMALG3(kyber90s768, 192),
    KEMALG2(kyber90s1024, 256),
    KEMALG3(hqc128, 128),
    KEMALG3(hqc192, 192),
    KEMALG2(hqc256, 256),
    KEMALG3(ntrulpr653, 128),
    KEMALG3(ntrulpr761, 128),
    KEMALG3(ntrulpr857, 192),
    KEMALG2(ntrulpr1277, 256),
    KEMALG3(sntrup653, 128),
    KEMALG3(sntrup761, 128),
    KEMALG3(sntrup857, 192),
    KEMALG2(sntrup1277, 256),
///// OQS_TEMPLATE_FRAGMENT_KEM_CASES_END
};

static int test_oqs_kems(const char *kemalg_name)
{
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *key = NULL;
  unsigned char *out, *secenc, *secdec;
  size_t outlen, seclen;

  int testresult = 1;

  if (!alg_is_enabled(kemalg_name)) {
     printf("Not testing disabled algorithm %s.\n", kemalg_name);
     return 1;
  }
  // test with built-in digest only if default provider is active:
  // TBD revisit when hybrids are activated: They always need default provider
  if (OSSL_PROVIDER_available(libctx, "default")) {
    testresult &=
      (ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name, NULL)) != NULL
      && EVP_PKEY_keygen_init(ctx)
      && EVP_PKEY_generate(ctx, &key);

    if (!testresult) goto err;
    OPENSSL_free(ctx);
    ctx = NULL;

    testresult &=
      (ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL)) != NULL
      && EVP_PKEY_encapsulate_init(ctx, NULL)
      && EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen)
      && (out = OPENSSL_malloc(outlen)) != NULL
      && (secenc = OPENSSL_malloc(seclen)) != NULL
      && memset(secenc, 0x11, seclen) != NULL
      && (secdec = OPENSSL_malloc(seclen)) != NULL
      && memset(secdec, 0xff, seclen) != NULL
      && EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen)
      && EVP_PKEY_decapsulate_init(ctx, NULL)
      && EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen)
      && memcmp(secenc, secdec, seclen) == 0;
    if (!testresult) goto err;

    out[0] = ~out[0];
    out[outlen - 1] = ~out[outlen - 1];
    testresult &=
      memset(secdec, 0xff, seclen) != NULL
      && EVP_PKEY_decapsulate_init(ctx, NULL)
      && (EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen) || 1)
      && memcmp(secenc, secdec, seclen) != 0;
  }

err:
  EVP_PKEY_free(key);
  OPENSSL_free(ctx);
  return testresult;
}

#define nelem(a) (sizeof(a)/sizeof((a)[0]))

int main(int argc, char *argv[])
{
  size_t i;
  int errcnt = 0, test = 0;

  T((libctx = OSSL_LIB_CTX_new()) != NULL);
  T(argc == 3);
  modulename = argv[1];
  configfile = argv[2];

  T(OSSL_LIB_CTX_load_config(libctx, configfile));

  T(OSSL_PROVIDER_available(libctx, modulename));

  for (i = 0; i < nelem(kemalg_names); i++) {
    if (test_oqs_kems(kemalg_names[i])) {
      fprintf(stderr,
              cGREEN "  KEM test succeeded: %s" cNORM "\n",
              kemalg_names[i]);
    } else {
      fprintf(stderr,
              cRED "  KEM test failed: %s" cNORM "\n",
              kemalg_names[i]);
      ERR_print_errors_fp(stderr);
      errcnt++;
    }
  }

  OSSL_LIB_CTX_free(libctx);

  TEST_ASSERT(errcnt == 0)
  return !test;
}
