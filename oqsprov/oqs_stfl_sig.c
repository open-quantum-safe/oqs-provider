// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider — Stateful signature (LMS) implementation.
 *
 * Exposes LMS (Leighton-Micali Signature, NIST SP 800-208 / RFC 8554)
 * through the OpenSSL provider signature dispatch interface.
 *
 * IMPORTANT: LMS is a stateful signature scheme.  Each signing operation
 * consumes one leaf of the Merkle tree.  The updated private key state MUST
 * be written back to persistent storage before reporting success; otherwise
 * the same one-time key could be reused, completely breaking security.
 *
 * This implementation delegates state storage to a simple file-based
 * callback (lms_store_sk_to_file).  The path is taken from the key's
 * stfl_state_file field; if that is NULL a default of
 * "<tls_name>_<pubkey_hex_prefix>.lms_state" in the directory given by
 * $OQS_STFL_STATE_DIR (or /tmp if unset) is used.
 *
 * Requirements:
 *   liboqs must have been built with:
 *     -DOQS_ENABLE_SIG_STFL_LMS=ON
 *     -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
 */

/*
 * Include oqs_prov.h FIRST so that oqsconfig.h is pulled in before the
 * OQS_ENABLE_SIG_STFL_LMS guard below is evaluated.  Without this, the
 * #ifdef would always be false because oqsconfig.h hasn't been seen yet.
 */
#include "oqs_prov.h"

#ifdef OQS_ENABLE_SIG_STFL_LMS

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "oqs/sig_stfl.h"
/* oqs_prov.h already included before the #ifdef guard above */

#ifdef NDEBUG
#define OQS_STFL_PRINTF(a)
#define OQS_STFL_PRINTF2(a, b)
#else
#define OQS_STFL_PRINTF(a)                                                     \
    if (getenv("OQSSTFL"))                                                     \
    fprintf(stderr, a)
#define OQS_STFL_PRINTF2(a, b)                                                 \
    if (getenv("OQSSTFL"))                                                     \
    fprintf(stderr, a, b)
#endif

/* Context for a single sign/verify operation. */
typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    OQSX_KEY *key;   /* ref-counted OQSX_KEY holding the LMS key */
    int operation;   /* EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY */
    /* Buffer for digest-sign/verify accumulated message bytes */
    unsigned char *msgbuf;
    size_t msgbuf_len;
    size_t msgbuf_alloc;
} PROV_OQSSTFL_CTX;

/* -------------------------------------------------------------------------
 * State-storage callback (secure_store_sk).
 *
 * Called by liboqs after every successful OQS_SIG_STFL_sign() to persist
 * the updated private key state.  `context` is a (char *) file path.
 *
 * We write to a temp file first and rename atomically to minimise the
 * window of a partial write.
 * ------------------------------------------------------------------------- */
static OQS_STATUS lms_store_sk_to_file(uint8_t *sk_buf, size_t buf_len,
                                       void *context) {
    const char *path = (const char *)context;
    char tmp_path[4096];

    if (!path || !sk_buf || buf_len == 0)
        return OQS_ERROR;

    /* Write to a sibling temp file, then rename. */
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >=
        (int)sizeof(tmp_path))
        return OQS_ERROR;

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        fprintf(stderr,
                "OQS LMS: Cannot open state file %s for writing: %s\n",
                tmp_path, strerror(errno));
        return OQS_ERROR;
    }

    int ok = (fwrite(sk_buf, 1, buf_len, f) == buf_len);
    fclose(f);

    if (!ok) {
        fprintf(stderr,
                "OQS LMS: Short write to state file %s\n", tmp_path);
        remove(tmp_path);
        return OQS_ERROR;
    }

    if (rename(tmp_path, path) != 0) {
        fprintf(stderr,
                "OQS LMS: Cannot rename %s -> %s: %s\n",
                tmp_path, path, strerror(errno));
        remove(tmp_path);
        return OQS_ERROR;
    }

    OQS_STFL_PRINTF2("OQS LMS: state saved to %s\n", path);
    return OQS_SUCCESS;
}

/*
 * Build the default state-file path when key->stfl_state_file is NULL.
 * Returns a heap-allocated string; caller must OPENSSL_free it.
 * Format: <dir>/<tls_name>_<first8hex>.lms_state
 */
static char *lms_default_state_path(const OQSX_KEY *key) {
    const char *dir = getenv("OQS_STFL_STATE_DIR");
    if (!dir || dir[0] == '\0')
        dir = "/tmp";

    /* hex-encode first 4 bytes of public key for uniqueness */
    char hex[9] = "00000000";
    if (key->pubkey && key->pubkeylen >= 4) {
        snprintf(hex, sizeof(hex), "%02x%02x%02x%02x",
                 ((unsigned char *)key->pubkey)[0],
                 ((unsigned char *)key->pubkey)[1],
                 ((unsigned char *)key->pubkey)[2],
                 ((unsigned char *)key->pubkey)[3]);
    }

    size_t len = strlen(dir) + 1 + strlen(key->tls_name) + 1 + 8 +
                 sizeof(".lms_state") + 1;
    char *path = OPENSSL_malloc(len);
    if (!path)
        return NULL;
    snprintf(path, len, "%s/%s_%s.lms_state", dir, key->tls_name, hex);
    return path;
}

/*
 * Attach the secure_store_sk callback to a live secret key object.
 * Uses key->stfl_state_file if set, otherwise derives a default path and
 * stores it back into key->stfl_state_file for later reuse.
 *
 * Returns 1 on success, 0 on failure.
 */
static int lms_attach_store_cb(OQSX_KEY *key) {
    if (!key->stfl_state_file) {
        key->stfl_state_file = lms_default_state_path(key);
        if (!key->stfl_state_file)
            return 0;
    }
    OQS_SIG_STFL_SECRET_KEY_SET_store_cb(key->stfl_secret_key,
                                          lms_store_sk_to_file,
                                          (void *)key->stfl_state_file);
    return 1;
}

/* -------------------------------------------------------------------------
 * Provider dispatch functions
 * ------------------------------------------------------------------------- */

static void *oqs_stfl_sig_newctx(void *provctx, const char *propq) {
    PROV_OQSSTFL_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    OQS_STFL_PRINTF("OQS STFL SIG: newctx called\n");
    if (!ctx)
        return NULL;

    ctx->libctx = PROV_OQS_LIBCTX_OF(provctx);
    if (propq) {
        ctx->propq = OPENSSL_strdup(propq);
        if (!ctx->propq) {
            OPENSSL_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

static void oqs_stfl_sig_freectx(void *vctx) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;

    OQS_STFL_PRINTF("OQS STFL SIG: freectx called\n");
    if (!ctx)
        return;
    oqsx_key_free(ctx->key);
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx->msgbuf);
    OPENSSL_free(ctx);
}

/* Shared init for sign and verify. */
static int oqs_stfl_sig_signverify_init(void *vctx, void *vkey, int operation) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQSX_KEY *key = (OQSX_KEY *)vkey;

    OQS_STFL_PRINTF("OQS STFL SIG: signverify_init called\n");

    if (!ctx || !key || !oqsx_key_up_ref(key))
        return 0;

    oqsx_key_free(ctx->key);
    ctx->key = key;
    ctx->operation = operation;

    if (operation == EVP_PKEY_OP_SIGN) {
        /* Need live secret key for signing */
        if (!key->stfl_secret_key) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_NO_PRIVATE_KEY);
            return 0;
        }
        /* Ensure the storage callback is wired up */
        if (!lms_attach_store_cb(key)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        /* Verification only needs the public key */
        if (!key->pubkey) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
            return 0;
        }
    }
    return 1;
}

static int oqs_stfl_sig_sign_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[]) {
    OQS_STFL_PRINTF("OQS STFL SIG: sign_init called\n");
    return oqs_stfl_sig_signverify_init(vctx, vkey, EVP_PKEY_OP_SIGN);
}

static int oqs_stfl_sig_verify_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[]) {
    OQS_STFL_PRINTF("OQS STFL SIG: verify_init called\n");
    return oqs_stfl_sig_signverify_init(vctx, vkey, EVP_PKEY_OP_VERIFY);
}

static int oqs_stfl_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQSX_KEY *key = ctx->key;
    OQS_SIG_STFL *stfl =
        key->oqsx_provider_ctx.oqsx_qs_ctx.sig_stfl;

    OQS_STFL_PRINTF("OQS STFL SIG: sign called\n");

    if (!stfl || !key->stfl_secret_key) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_NO_PRIVATE_KEY);
        return 0;
    }

    if (sig == NULL) {
        /* Caller querying required buffer size */
        *siglen = stfl->length_signature;
        return 1;
    }
    if (sigsize < stfl->length_signature) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_BUFFER_LENGTH_WRONG);
        return 0;
    }

    OQS_STATUS rc = OQS_SIG_STFL_sign(stfl, sig, siglen, tbs, tbslen,
                                       key->stfl_secret_key);
    if (rc != OQS_SUCCESS) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_SIGNING_FAILED);
        return 0;
    }
    return 1;
}

static int oqs_stfl_sig_verify(void *vctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQSX_KEY *key = ctx->key;
    OQS_SIG_STFL *stfl =
        key->oqsx_provider_ctx.oqsx_qs_ctx.sig_stfl;

    OQS_STFL_PRINTF("OQS STFL SIG: verify called\n");

    if (!stfl || !key->pubkey) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }

    OQS_STATUS rc = OQS_SIG_STFL_verify(stfl, tbs, tbslen, sig, siglen,
                                         (const uint8_t *)key->pubkey);
    if (rc != OQS_SUCCESS) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_VERIFY_ERROR);
        return 0;
    }
    return 1;
}

/* dupctx: duplicate the context including the accumulated message buffer */
static void *oqs_stfl_sig_dupctx(void *vctx) {
    PROV_OQSSTFL_CTX *src = (PROV_OQSSTFL_CTX *)vctx;
    PROV_OQSSTFL_CTX *dst = OPENSSL_zalloc(sizeof(*dst));

    OQS_STFL_PRINTF("OQS STFL SIG: dupctx called\n");
    if (!dst)
        return NULL;

    dst->libctx = src->libctx;
    dst->operation = src->operation;
    if (src->propq) {
        dst->propq = OPENSSL_strdup(src->propq);
        if (!dst->propq)
            goto err;
    }
    if (src->key) {
        oqsx_key_up_ref(src->key);
        dst->key = src->key;
    }
    /* Copy accumulated message buffer */
    if (src->msgbuf && src->msgbuf_len > 0) {
        dst->msgbuf = OPENSSL_malloc(src->msgbuf_len);
        if (!dst->msgbuf)
            goto err;
        memcpy(dst->msgbuf, src->msgbuf, src->msgbuf_len);
        dst->msgbuf_len = src->msgbuf_len;
        dst->msgbuf_alloc = src->msgbuf_len;
    }
    return dst;
err:
    OPENSSL_free(dst->propq);
    if (dst->key)
        oqsx_key_free(dst->key);
    OPENSSL_free(dst->msgbuf);
    OPENSSL_free(dst);
    return NULL;
}

/* Minimal gettable/settable ctx params — no MD for stateful sigs */
static const OSSL_PARAM *oqs_stfl_sig_gettable_ctx_params(void *vctx,
                                                            void *provctx) {
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_END};
    return known_gettable_ctx_params;
}

static int oqs_stfl_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    return 1; /* nothing to report */
}

static const OSSL_PARAM *oqs_stfl_sig_settable_ctx_params(void *vctx,
                                                            void *provctx) {
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_END};
    return known_settable_ctx_params;
}

static int oqs_stfl_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    return 1; /* nothing to configure */
}

/* -------------------------------------------------------------------------
 * Digest-sign / digest-verify (message buffering approach)
 *
 * LMS signs the raw message without pre-hashing.  We buffer the message
 * across update calls and call sign()/verify() in the final step.
 * ------------------------------------------------------------------------- */

/* Grow the message buffer to hold at least `needed` more bytes. */
static int stfl_msgbuf_grow(PROV_OQSSTFL_CTX *ctx, size_t needed) {
    size_t newalloc = ctx->msgbuf_alloc;
    if (newalloc == 0)
        newalloc = 4096;
    while (newalloc < ctx->msgbuf_len + needed)
        newalloc *= 2;
    if (newalloc != ctx->msgbuf_alloc) {
        unsigned char *nb = OPENSSL_realloc(ctx->msgbuf, newalloc);
        if (!nb)
            return 0;
        ctx->msgbuf = nb;
        ctx->msgbuf_alloc = newalloc;
    }
    return 1;
}

static int oqs_stfl_sig_digest_sign_init(void *vctx, const char *mdname,
                                          void *vkey,
                                          const OSSL_PARAM params[]) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQS_STFL_PRINTF("OQS STFL SIG: digest_sign_init called\n");
    /* LMS doesn't use a hash — ignore mdname */
    ctx->msgbuf_len = 0;
    return oqs_stfl_sig_signverify_init(vctx, vkey, EVP_PKEY_OP_SIGN);
}

static int oqs_stfl_sig_digest_verify_init(void *vctx, const char *mdname,
                                            void *vkey,
                                            const OSSL_PARAM params[]) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQS_STFL_PRINTF("OQS STFL SIG: digest_verify_init called\n");
    ctx->msgbuf_len = 0;
    return oqs_stfl_sig_signverify_init(vctx, vkey, EVP_PKEY_OP_VERIFY);
}

static int oqs_stfl_sig_digest_signverify_update(void *vctx,
                                                  const unsigned char *data,
                                                  size_t datalen) {
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    OQS_STFL_PRINTF("OQS STFL SIG: digest_signverify_update called\n");
    if (!stfl_msgbuf_grow(ctx, datalen))
        return 0;
    memcpy(ctx->msgbuf + ctx->msgbuf_len, data, datalen);
    ctx->msgbuf_len += datalen;
    return 1;
}

static int oqs_stfl_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize) {
    OQS_STFL_PRINTF("OQS STFL SIG: digest_sign_final called\n");
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    return oqs_stfl_sig_sign(vctx, sig, siglen, sigsize,
                              ctx->msgbuf, ctx->msgbuf_len);
}

static int oqs_stfl_sig_digest_verify_final(void *vctx,
                                             const unsigned char *sig,
                                             size_t siglen) {
    OQS_STFL_PRINTF("OQS STFL SIG: digest_verify_final called\n");
    PROV_OQSSTFL_CTX *ctx = (PROV_OQSSTFL_CTX *)vctx;
    return oqs_stfl_sig_verify(vctx, sig, siglen,
                                ctx->msgbuf, ctx->msgbuf_len);
}

/* -------------------------------------------------------------------------
 * Dispatch table
 * ------------------------------------------------------------------------- */
const OSSL_DISPATCH oqs_stfl_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))oqs_stfl_sig_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))oqs_stfl_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))oqs_stfl_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))oqs_stfl_sig_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))oqs_stfl_sig_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))oqs_stfl_sig_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))oqs_stfl_sig_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
     (void (*)(void))oqs_stfl_sig_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
     (void (*)(void))oqs_stfl_sig_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
     (void (*)(void))oqs_stfl_sig_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
     (void (*)(void))oqs_stfl_sig_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
     (void (*)(void))oqs_stfl_sig_digest_signverify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
     (void (*)(void))oqs_stfl_sig_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
     (void (*)(void))oqs_stfl_sig_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
     (void (*)(void))oqs_stfl_sig_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
     (void (*)(void))oqs_stfl_sig_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))oqs_stfl_sig_settable_ctx_params},
    {0, NULL}};

#endif /* OQS_ENABLE_SIG_STFL_LMS */
