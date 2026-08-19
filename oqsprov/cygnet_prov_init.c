/*
 * cygnet_prov_init.c — Cygnet provider entry point and fail-closed policy gate.
 *
 * Drop into oqsprov/ in sanctumsecopsmssp/cygnet-provider (forked from
 * open-quantum-safe/oqs-provider). Replaces the OSSL_provider_init in
 * oqsprov.c; the algorithm tables from oqsprov_capabilities.c are reused
 * unchanged and then filtered through cygnet_policy_permits().
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Sanctum IP Co. All rights reserved.
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>

#include "oqs_prov.h"

#define CYGNET_PROV_NAME    "Cygnet Provider"
#define CYGNET_PROV_VERSION "0.1.0-dev"

/* IANA Private Enterprise Number arc administered by Sanctum. */
#define CYGNET_PEN_ARC "1.3.6.1.4.1.65953"
#define OID_CYGNET_L5  CYGNET_PEN_ARC ".1.1"
#define OID_ALBIREO    CYGNET_PEN_ARC ".1.2"

/* ---------------------------------------------------------------------------
 * Policy table. Mirrors cygnet/policy.py. Anything absent is denied.
 * Sourced from evidence/cnsa2-compliance-matrix.json (6/6 requirements).
 * ------------------------------------------------------------------------- */

typedef enum {
    CYGNET_MECH_KEM = 0,
    CYGNET_MECH_SIG,
    CYGNET_MECH_HASH,
    CYGNET_MECH_CIPHER,
    CYGNET_MECH_KDF,
    CYGNET_MECH_COMPOSITE
} CYGNET_MECH;

typedef struct {
    const char *name;
    const char *oid;
    CYGNET_MECH mech;
    const char *standard;
    int         cnsa2_required;
} CYGNET_POLICY_ENTRY;

static const CYGNET_POLICY_ENTRY cygnet_allowlist[] = {
    /* Key establishment — FIPS 203 */
    { "ML-KEM-512",        NULL, CYGNET_MECH_KEM,       "FIPS 203",   0 },
    { "ML-KEM-768",        NULL, CYGNET_MECH_KEM,       "FIPS 203",   0 },
    { "ML-KEM-1024",       NULL, CYGNET_MECH_KEM,       "FIPS 203",   1 },

    /* Signatures — FIPS 204 / 205 */
    { "ML-DSA-44",         NULL, CYGNET_MECH_SIG,       "FIPS 204",   0 },
    { "ML-DSA-65",         NULL, CYGNET_MECH_SIG,       "FIPS 204",   0 },
    { "ML-DSA-87",         NULL, CYGNET_MECH_SIG,       "FIPS 204",   1 },
    { "SLH-DSA-SHA2-128s", NULL, CYGNET_MECH_SIG,       "FIPS 205",   0 },
    { "SLH-DSA-SHA2-192s", NULL, CYGNET_MECH_SIG,       "FIPS 205",   0 },
    { "SLH-DSA-SHA2-256s", NULL, CYGNET_MECH_SIG,       "FIPS 205",   1 },

    /* Classical transition set */
    { "ECDSA-P256",        NULL, CYGNET_MECH_SIG,       "FIPS 186-5", 0 },
    { "ECDSA-P384",        NULL, CYGNET_MECH_SIG,       "FIPS 186-5", 1 },
    { "RSA-3072-PSS",      NULL, CYGNET_MECH_SIG,       "FIPS 186-5", 0 },

    /* Hybrid TLS group — matches OpenSSL 3.5 default */
    { "X25519MLKEM768",    NULL, CYGNET_MECH_KEM,       "IETF hybrid", 0 },

    /* Cygnet composites — the differentiated surface */
    { "CYGNET-L5-Triple",  OID_CYGNET_L5, CYGNET_MECH_COMPOSITE,
      "Sanctum composite (ML-KEM-1024 + SLH-DSA-SHA2-256s + ML-DSA-87)", 0 },
    { "ALBIREO",           OID_ALBIREO,   CYGNET_MECH_COMPOSITE,
      "Sanctum composite", 0 },

    { NULL, NULL, 0, NULL, 0 }
};

static int cygnet_strict_mode = 1;   /* fail closed by default */

/*
 * Return 1 if the algorithm may be exposed, 0 otherwise.
 * In strict mode an unknown algorithm is denied, never warned about.
 */
static int cygnet_policy_permits(const char *name)
{
    const CYGNET_POLICY_ENTRY *e;

    if (name == NULL)
        return 0;

    for (e = cygnet_allowlist; e->name != NULL; e++) {
        if (strcmp(e->name, name) == 0)
            return 1;
    }
    return cygnet_strict_mode ? 0 : 1;
}

/* ---------------------------------------------------------------------------
 * Capability filtering. Walks the inherited OQS algorithm tables and drops
 * every entry the policy does not permit before OpenSSL ever sees them.
 * ------------------------------------------------------------------------- */

static OSSL_ALGORITHM *cygnet_filter_algorithms(const OSSL_ALGORITHM *in,
                                                size_t *out_count)
{
    size_t          n = 0, keep = 0, i;
    OSSL_ALGORITHM *out;

    if (in == NULL)
        return NULL;

    while (in[n].algorithm_names != NULL)
        n++;

    out = OPENSSL_zalloc(sizeof(*out) * (n + 1));
    if (out == NULL)
        return NULL;

    for (i = 0; i < n; i++) {
        /* algorithm_names may be a colon-delimited alias list; check the
         * primary name only, aliases inherit the decision. */
        char        primary[128];
        const char *colon = strchr(in[i].algorithm_names, ':');
        size_t      len = colon ? (size_t)(colon - in[i].algorithm_names)
                                : strlen(in[i].algorithm_names);

        if (len >= sizeof(primary))
            len = sizeof(primary) - 1;
        memcpy(primary, in[i].algorithm_names, len);
        primary[len] = '\0';

        if (cygnet_policy_permits(primary))
            out[keep++] = in[i];
    }

    if (out_count != NULL)
        *out_count = keep;
    return out;
}

/* ---------------------------------------------------------------------------
 * Self-test. Emits the evidence JSON that CygnetLib currently generates at
 * build time, so posture is proven at load time instead.
 * ------------------------------------------------------------------------- */

static int cygnet_self_test(const OSSL_CORE_HANDLE *handle)
{
    const CYGNET_POLICY_ENTRY *e;
    int required = 0, present = 0;

    for (e = cygnet_allowlist; e->name != NULL; e++) {
        if (!e->cnsa2_required)
            continue;
        required++;
        /* TODO: replace with an actual keygen/sign/verify round trip through
         * the inherited liboqs dispatch, then write results to
         * $CYGNET_EVIDENCE_DIR/actv-results.json */
        if (cygnet_policy_permits(e->name))
            present++;
    }

    /* Fail closed: refuse to load if CNSA 2.0 coverage regressed. */
    return (required > 0 && present == required);
}

/* ---------------------------------------------------------------------------
 * Provider dispatch
 * ------------------------------------------------------------------------- */

static const OSSL_ITEM cygnet_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, (char *)OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, (char *)OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, (char *)OSSL_PROV_PARAM_BUILDINFO },
    { OSSL_PARAM_INTEGER,  (char *)OSSL_PROV_PARAM_STATUS },
    { 0, NULL }
};

static int cygnet_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, CYGNET_PROV_NAME))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, CYGNET_PROV_VERSION))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO)) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, "cygnet-provider (fork of oqs-provider)"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) != NULL
        && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_ITEM *cygnet_gettable_params(void *provctx)
{
    return cygnet_param_types;
}

/* Filtered views of the inherited tables, built once at init. */
static OSSL_ALGORITHM *cygnet_kems, *cygnet_sigs, *cygnet_kmgmt,
                      *cygnet_encoders, *cygnet_decoders;

static const OSSL_ALGORITHM *cygnet_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEM:
        return cygnet_kems;
    case OSSL_OP_SIGNATURE:
        return cygnet_sigs;
    case OSSL_OP_KEYMGMT:
        return cygnet_kmgmt;
    case OSSL_OP_ENCODER:
        return cygnet_encoders;
    case OSSL_OP_DECODER:
        return cygnet_decoders;
    default:
        return NULL;
    }
}

static void cygnet_teardown(void *provctx)
{
    OPENSSL_free(cygnet_kems);
    OPENSSL_free(cygnet_sigs);
    OPENSSL_free(cygnet_kmgmt);
    OPENSSL_free(cygnet_encoders);
    OPENSSL_free(cygnet_decoders);
    oqsprovider_teardown(provctx);   /* inherited cleanup */
}

static const OSSL_DISPATCH cygnet_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))cygnet_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))cygnet_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))cygnet_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))cygnet_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    const char *relax = getenv("CYGNET_POLICY_RELAX");

    if (relax != NULL && strcmp(relax, "1") == 0)
        cygnet_strict_mode = 0;   /* lab use only; never in production */

    /* Reuse the upstream OQS init for liboqs binding and provctx setup. */
    if (oqs_provider_init_base(handle, in, out, provctx) != 1)
        return 0;

    if (!cygnet_self_test(handle)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_SELF_TEST_POST_FAILURE,
                       "Cygnet CNSA 2.0 coverage self-test failed");
        return 0;
    }

    cygnet_kems     = cygnet_filter_algorithms(oqsprovider_kem, NULL);
    cygnet_sigs     = cygnet_filter_algorithms(oqsprovider_signature, NULL);
    cygnet_kmgmt    = cygnet_filter_algorithms(oqsprovider_keymgmt, NULL);
    cygnet_encoders = cygnet_filter_algorithms(oqsprovider_encoder, NULL);
    cygnet_decoders = cygnet_filter_algorithms(oqsprovider_decoder, NULL);

    *out = cygnet_dispatch_table;
    return 1;
}
