/*!
 * Copyrights
 *
 * Portions created or assigned to ZmartZone Holding B.V. are
 * Copyright (c) 2018-2025 ZmartZone Holding B.V.  All Rights Reserved.
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include "include/jwk_int.h"
#include "include/util_int.h"

#include <cjose/base64.h>
#include <cjose/util.h>

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

// internal data structures

static const char CJOSE_JWK_EC_P_256_STR[] = "P-256";
static const char CJOSE_JWK_EC_P_384_STR[] = "P-384";
static const char CJOSE_JWK_EC_P_521_STR[] = "P-521";
static const char CJOSE_JWK_KTY_STR[] = "kty";
static const char CJOSE_JWK_KID_STR[] = "kid";
static const char CJOSE_JWK_KTY_EC_STR[] = "EC";
static const char CJOSE_JWK_KTY_RSA_STR[] = "RSA";
static const char CJOSE_JWK_KTY_OCT_STR[] = "oct";
static const char CJOSE_JWK_KTY_OKP_STR[] = "OKP";
static const char CJOSE_JWK_OKP_ED25519_STR[] = "Ed25519";
static const char CJOSE_JWK_OKP_ED448_STR[] = "Ed448";
static const char CJOSE_JWK_OKP_X25519_STR[] = "X25519";
static const char CJOSE_JWK_OKP_X448_STR[] = "X448";
static const char CJOSE_JWK_CRV_STR[] = "crv";
static const char CJOSE_JWK_X_STR[] = "x";
static const char CJOSE_JWK_Y_STR[] = "y";
static const char CJOSE_JWK_D_STR[] = "d";
static const char CJOSE_JWK_N_STR[] = "n";
static const char CJOSE_JWK_E_STR[] = "e";
static const char CJOSE_JWK_P_STR[] = "p";
static const char CJOSE_JWK_Q_STR[] = "q";
static const char CJOSE_JWK_DP_STR[] = "dp";
static const char CJOSE_JWK_DQ_STR[] = "dq";
static const char CJOSE_JWK_QI_STR[] = "qi";
static const char CJOSE_JWK_K_STR[] = "k";

static const char *JWK_KTY_NAMES[] = { CJOSE_JWK_KTY_RSA_STR, CJOSE_JWK_KTY_EC_STR, CJOSE_JWK_KTY_OCT_STR, CJOSE_JWK_KTY_OKP_STR };

static void _cjose_jwk_rsa_get(EVP_PKEY *pkey, BIGNUM **rsa_n, BIGNUM **rsa_e, BIGNUM **rsa_d)
{
    if (pkey == NULL)
        return;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, rsa_n);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, rsa_e);
    if (rsa_d)
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, rsa_d);
}

bool _cjose_jwk_rsa_set(EVP_PKEY *pkey, uint8_t *n, size_t n_len, uint8_t *e, size_t e_len, uint8_t *d, size_t d_len)
{
    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;

    if (pkey == NULL)
        return false;

    if ((n == NULL) || (n_len <= 0) || (e == NULL) || (e_len <= 0))
        return false;

    if (n && n_len > 0)
        rsa_n = BN_bin2bn(n, n_len, NULL);
    if (e && e_len > 0)
        rsa_e = BN_bin2bn(e, e_len, NULL);
    if (d && d_len > 0)
        rsa_d = BN_bin2bn(d, d_len, NULL);

    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, rsa_n);
    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, rsa_e);
    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, rsa_d);

    return true;
}

void _cjose_jwk_rsa_get_factors(EVP_PKEY *pkey, BIGNUM **p, BIGNUM **q)
{
    if (pkey == NULL)
        return;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
}

void _cjose_jwk_rsa_set_factors(EVP_PKEY *pkey, uint8_t *p, size_t p_len, uint8_t *q, size_t q_len)
{
    BIGNUM *rsa_p = NULL, *rsa_q = NULL;

    if (pkey == NULL)
        return;

    if (p && p_len > 0)
        rsa_p = BN_bin2bn(p, p_len, NULL);
    if (q && q_len > 0)
        rsa_q = BN_bin2bn(q, q_len, NULL);

    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, rsa_p);
    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, rsa_q);
}

void _cjose_jwk_rsa_get_crt(EVP_PKEY *pkey, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
    if (pkey == NULL)
        return;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp);
}

void _cjose_jwk_rsa_set_crt(
    EVP_PKEY *pkey, uint8_t *dmp1, size_t dmp1_len, uint8_t *dmq1, size_t dmq1_len, uint8_t *iqmp, size_t iqmp_len)
{
    BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;

    if (pkey == NULL)
        return;

    if (dmp1 && dmp1_len > 0)
        rsa_dmp1 = BN_bin2bn(dmp1, dmp1_len, NULL);
    if (dmq1 && dmq1_len > 0)
        rsa_dmq1 = BN_bin2bn(dmq1, dmq1_len, NULL);
    if (iqmp && iqmp_len > 0)
        rsa_iqmp = BN_bin2bn(iqmp, iqmp_len, NULL);

    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, rsa_dmp1);
    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, rsa_dmq1);
    EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, rsa_iqmp);
}

// interface functions -- Generic

const char *cjose_jwk_name_for_kty(cjose_jwk_kty_t kty, cjose_err *err)
{
    if (0 == kty || CJOSE_JWK_KTY_OKP < kty)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return JWK_KTY_NAMES[kty - CJOSE_JWK_KTY_RSA];
}

cjose_jwk_t *cjose_jwk_retain(cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ++(jwk->retained);
    // TODO: check for overflow

    return jwk;
}

bool cjose_jwk_release(cjose_jwk_t *jwk)
{
    if (!jwk)
    {
        return false;
    }

    --(jwk->retained);
    if (0 == jwk->retained)
    {
        cjose_get_dealloc()(jwk->kid);
        jwk->kid = NULL;

        // assumes freefunc is set
        if (NULL != jwk->fns->free_func)
        {
            jwk->fns->free_func(jwk);
        }
        jwk = NULL;
    }

    return (NULL != jwk);
}

cjose_jwk_kty_t cjose_jwk_get_kty(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return -1;
    }

    return jwk->kty;
}
size_t cjose_jwk_get_keysize(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return 0;
    }
    return jwk->keysize;
}

void *cjose_jwk_get_keydata(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    return jwk->keydata;
}

const char *cjose_jwk_get_kid(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    return jwk->kid;
}

bool cjose_jwk_set_kid(cjose_jwk_t *jwk, const char *kid, size_t len, cjose_err *err)
{
    if (!jwk || !kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    if (jwk->kid)
    {
        cjose_get_dealloc()(jwk->kid);
    }
    jwk->kid = (char *)cjose_get_alloc()(len + 1);
    if (!jwk->kid)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    strncpy(jwk->kid, kid, len + 1);
    return true;
}

char *cjose_jwk_to_json(const cjose_jwk_t *jwk, bool priv, cjose_err *err)
{
    char *result = NULL;

    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    json_t *json = json_object(), *field = NULL;
    if (!json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }

    // set kty
    const char *kty = cjose_jwk_name_for_kty(jwk->kty, err);
    field = json_string(kty);
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    json_object_set(json, "kty", field);
    json_decref(field);
    field = NULL;

    // set kid
    if (NULL != jwk->kid)
    {
        field = json_string(jwk->kid);
        if (!field)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto to_json_cleanup;
        }
        json_object_set(json, CJOSE_JWK_KID_STR, field);
        json_decref(field);
        field = NULL;
    }

    // set public fields
    if (jwk->fns->public_json && !jwk->fns->public_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // set private fields
    if (priv && jwk->fns->private_json && !jwk->fns->private_json(jwk, json, err))
    {
        goto to_json_cleanup;
    }

    // generate the string ...
    char *str_jwk = json_dumps(json, JSON_ENCODE_ANY | JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (!str_jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto to_json_cleanup;
    }
    result = _cjose_strndup(str_jwk, -1, err);
    if (!result)
    {
        cjose_get_dealloc()(str_jwk);
        goto to_json_cleanup;
    }
    cjose_get_dealloc()(str_jwk);

to_json_cleanup:

    if (json)
    {
        json_decref(json);
        json = NULL;
    }

    return result;
}

//////////////// Octet String ////////////////
// internal data & functions -- Octet String

static void _oct_free(cjose_jwk_t *jwk);
static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OCT_FNTABLE = { _oct_free, _oct_public_fields, _oct_private_fields };

static cjose_jwk_t *_oct_new(uint8_t *buffer, size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = (cjose_jwk_t *)cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
    }
    else
    {
        memset(jwk, 0, sizeof(cjose_jwk_t));
        jwk->retained = 1;
        jwk->kty = CJOSE_JWK_KTY_OCT;
        jwk->keysize = keysize;
        jwk->keydata = buffer;
        jwk->fns = &OCT_FNTABLE;
    }

    return jwk;
}

static void _oct_free(cjose_jwk_t *jwk)
{
    uint8_t *buffer = (uint8_t *)jwk->keydata;
    jwk->keydata = NULL;
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    cjose_get_dealloc()(jwk);
}

static bool _oct_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err) { return true; }

static bool _oct_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    char *k = NULL;
    size_t klen = 0;
    uint8_t *keydata = (uint8_t *)jwk->keydata;
    size_t keysize = jwk->keysize / 8;

    if (!cjose_base64url_encode(keydata, keysize, &k, &klen, err))
    {
        return false;
    }

    field = _cjose_json_stringn(k, klen, err);
    cjose_get_dealloc()(k);
    k = NULL;
    if (!field)
    {
        return false;
    }
    json_object_set(json, "k", field);
    json_decref(field);

    return true;
}

// interface functions -- Octet String

cjose_jwk_t *cjose_jwk_create_oct_random(size_t keysize, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    // resize to bytes
    size_t buffersize = sizeof(uint8_t) * (keysize / 8);

    buffer = (uint8_t *)cjose_get_alloc()(buffersize);
    if (NULL == buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    if (1 != RAND_bytes(buffer, buffersize))
    {
        goto create_oct_failed;
    }

    jwk = _oct_new(buffer, keysize, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }
    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_oct_spec(const uint8_t *data, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *buffer = NULL;

    if (NULL == data || 0 == len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_oct_failed;
    }

    buffer = (uint8_t *)cjose_get_alloc()(len);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_oct_failed;
    }
    memcpy(buffer, data, len);

    jwk = _oct_new(buffer, len * 8, err);
    if (NULL == jwk)
    {
        goto create_oct_failed;
    }

    return jwk;

create_oct_failed:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
        buffer = NULL;
    }

    return NULL;
}

//////////////// Elliptic Curve ////////////////
// internal data & functions -- Elliptic Curve

static void _EC_free(cjose_jwk_t *jwk);
static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable EC_FNTABLE = { _EC_free, _EC_public_fields, _EC_private_fields };

static inline uint8_t _ec_size_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return 32;
    case CJOSE_JWK_EC_P_384:
        return 48;
    case CJOSE_JWK_EC_P_521:
        return 66;
    case CJOSE_JWK_EC_INVALID:
        return 0;
    }

    return 0;
}

static inline const char *_ec_name_for_curve(cjose_jwk_ec_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        return CJOSE_JWK_EC_P_256_STR;
    case CJOSE_JWK_EC_P_384:
        return CJOSE_JWK_EC_P_384_STR;
    case CJOSE_JWK_EC_P_521:
        return CJOSE_JWK_EC_P_521_STR;
    case CJOSE_JWK_EC_INVALID:
        return NULL;
    }

    return NULL;
}

static inline bool _ec_curve_from_name(const char *name, cjose_jwk_ec_curve *crv, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_EC_P_256_STR, sizeof(CJOSE_JWK_EC_P_256_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_256;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_384_STR, sizeof(CJOSE_JWK_EC_P_384_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_384;
    }
    else if (strncmp(name, CJOSE_JWK_EC_P_521_STR, sizeof(CJOSE_JWK_EC_P_521_STR)) == 0)
    {
        *crv = CJOSE_JWK_EC_P_521;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static inline bool _kty_from_name(const char *name, cjose_jwk_kty_t *kty, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_KTY_EC_STR, sizeof(CJOSE_JWK_KTY_EC_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_EC;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_RSA_STR, sizeof(CJOSE_JWK_KTY_RSA_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_RSA;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_OCT_STR, sizeof(CJOSE_JWK_KTY_OCT_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OCT;
    }
    else if (strncmp(name, CJOSE_JWK_KTY_OKP_STR, sizeof(CJOSE_JWK_KTY_OKP_STR)) == 0)
    {
        *kty = CJOSE_JWK_KTY_OKP;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static cjose_jwk_t *_EC_new(cjose_jwk_ec_curve crv, EVP_PKEY *ec, cjose_err *err)
{
    ec_keydata *keydata = cjose_get_alloc()(sizeof(ec_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = ec;

    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        cjose_get_dealloc()(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_EC;
    switch (crv)
    {
    case CJOSE_JWK_EC_P_256:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_EC_P_384:
        jwk->keysize = 384;
        break;
    case CJOSE_JWK_EC_P_521:
        jwk->keysize = 521;
        break;
    case CJOSE_JWK_EC_INVALID:
        // should never happen
        jwk->keysize = 0;
        break;
    }
    jwk->keydata = keydata;
    jwk->fns = &EC_FNTABLE;

    return jwk;
}

static void _EC_free(cjose_jwk_t *jwk)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EVP_PKEY *ec = keydata->key;
        keydata->key = NULL;
        if (ec)
        {
            EVP_PKEY_free(ec);
        }
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static bool _EC_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    BIGNUM *bnX = NULL, *bnY = NULL;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0, offset = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

    // output the curve
    field = json_string(_ec_name_for_curve(keydata->crv, err));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    buffer = cjose_get_alloc()(numsize);
    if (EVP_PKEY_get_bn_param(keydata->key, OSSL_PKEY_PARAM_EC_PUB_X, &bnX) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }
    if (EVP_PKEY_get_bn_param(keydata->key, OSSL_PKEY_PARAM_EC_PUB_Y, &bnY) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _ec_to_string_cleanup;
    }

    // output the x coordinate
    offset = numsize - BN_num_bytes(bnX);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnX, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    // output the y coordinate
    offset = numsize - BN_num_bytes(bnY);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnY, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "y", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_ec_to_string_cleanup:
    if (bnX)
    {
        BN_free(bnX);
    }
    if (bnY)
    {
        BN_free(bnY);
    }
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
    }

    return result;
}

static bool _EC_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    BIGNUM *bnD = NULL;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0, offset = 0;
    json_t *field = NULL;
    bool result = false;

    EVP_PKEY_get_bn_param(keydata->key, OSSL_PKEY_PARAM_PRIV_KEY, &bnD);
    // short circuit if 'd' is NULL or 0
    if (!bnD || BN_is_zero(bnD))
    {
        return true;
    }

    // track expected binary data size
    uint8_t numsize = _ec_size_for_curve(keydata->crv, err);

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _ec_to_string_cleanup;
    }

    offset = numsize - BN_num_bytes(bnD);
    memset(buffer, 0, numsize);
    BN_bn2bin(bnD, (buffer + offset));
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _ec_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _ec_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_ec_to_string_cleanup:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (bnD)
    {
        BN_free(bnD);
    }
    return result;
}

// interface functions -- Elliptic Curve

cjose_jwk_t *cjose_jwk_create_EC_random(cjose_jwk_ec_curve crv, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *pkey = NULL;

    const char *curve = _ec_name_for_curve(crv, err);
    if (curve == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_EC_failed;
    }

    pkey = EVP_EC_gen(curve);
    if (pkey == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    jwk = _EC_new(crv, pkey, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    return jwk;

create_EC_failed:

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_EC_spec(const cjose_jwk_ec_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bnD = NULL;
    BIGNUM *bnX = NULL;
    BIGNUM *bnY = NULL;
    EC_GROUP *group = NULL;
    unsigned char *buf = NULL;
    int len = 0;
    EC_POINT *Q = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool hasPub = ((NULL != spec->x && 0 < spec->xlen) && (NULL != spec->y && 0 < spec->ylen));
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    group = EC_GROUP_new_by_curve_name(spec->crv);
    if (group == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    if (OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2ln(spec->crv), 0) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    if (hasPriv)
    {
        bnD = BN_bin2bn(spec->d, spec->dlen, NULL);
        if (NULL == bnD)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }

        // calculate public key from private
        Q = EC_POINT_new(group);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_mul(group, Q, bnD, NULL, NULL, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }

        if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, bnD) != 1)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }

        // public key is set below
        // ignore provided public key!
        hasPub = false;
    }
    if (hasPub)
    {
        Q = EC_POINT_new(group);
        if (NULL == Q)
        {
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
            goto create_EC_failed;
        }
        bnX = BN_bin2bn(spec->x, spec->xlen, NULL);
        bnY = BN_bin2bn(spec->y, spec->ylen, NULL);
        if (!bnX || !bnY)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }

        if (1 != EC_POINT_set_affine_coordinates(group, Q, bnX, bnY, NULL))
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_EC_failed;
        }
    }

    len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (len == 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }
    buf = cjose_get_alloc()(len);
    if (buf == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    if (EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, buf, len, NULL) != len)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }
    if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, buf, len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_EC_failed;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey,
                          (hasPriv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY : OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
                              | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                          params)
        != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_EC_failed;
    }

    jwk = _EC_new(spec->crv, pkey, err);
    if (!jwk)
    {
        goto create_EC_failed;
    }

    // jump to cleanup
    goto create_EC_cleanup;

create_EC_failed:

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

create_EC_cleanup:

    if (buf)
    {
        cjose_get_dealloc()(buf);
        buf = NULL;
    }
    if (Q)
    {
        EC_POINT_free(Q);
        Q = NULL;
    }
    if (bnD)
    {
        BN_free(bnD);
        bnD = NULL;
    }
    if (bnX)
    {
        BN_free(bnX);
        bnX = NULL;
    }
    if (bnY)
    {
        BN_free(bnY);
        bnY = NULL;
    }
    if (param_bld)
    {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params)
    {
        OSSL_PARAM_free(params);
    }
    if (group)
    {
        EC_GROUP_free(group);
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return jwk;
}

const cjose_jwk_ec_curve cjose_jwk_EC_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jwk || CJOSE_JWK_KTY_EC != cjose_jwk_get_kty(jwk, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return CJOSE_JWK_EC_INVALID;
    }

    ec_keydata *keydata = jwk->keydata;
    return keydata->crv;
}

//////////////// RSA ////////////////
// internal data & functions -- RSA

static void _RSA_free(cjose_jwk_t *jwk);
static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable RSA_FNTABLE = { _RSA_free, _RSA_public_fields, _RSA_private_fields };

static inline cjose_jwk_t *_RSA_new(EVP_PKEY *rsa, cjose_err *err)
{
    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_RSA;
    jwk->keysize = EVP_PKEY_get_size(rsa) * 8;
    jwk->keydata = rsa;
    jwk->fns = &RSA_FNTABLE;

    return jwk;
}

static void _RSA_free(cjose_jwk_t *jwk)
{
    EVP_PKEY *rsa = (EVP_PKEY *)jwk->keydata;
    jwk->keydata = NULL;
    if (rsa)
    {
        EVP_PKEY_free(rsa);
    }
    cjose_get_dealloc()(jwk);
}

static inline bool _RSA_json_field(BIGNUM *param, const char *name, json_t *json, cjose_err *err)
{
    json_t *field = NULL;
    uint8_t *data = NULL;
    char *b64u = NULL;
    size_t datalen = 0, b64ulen = 0;
    bool result = false;

    if (!param)
    {
        return true;
    }

    datalen = BN_num_bytes(param);
    data = cjose_get_alloc()(sizeof(uint8_t) * datalen);
    if (!data)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto RSA_json_field_cleanup;
    }
    BN_bn2bin(param, data);
    if (!cjose_base64url_encode(data, datalen, &b64u, &b64ulen, err))
    {
        goto RSA_json_field_cleanup;
    }
    field = _cjose_json_stringn(b64u, b64ulen, err);
    if (!field)
    {
        goto RSA_json_field_cleanup;
    }
    json_object_set(json, name, field);
    json_decref(field);
    field = NULL;
    result = true;

RSA_json_field_cleanup:
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
        b64u = NULL;
    }
    if (data)
    {
        cjose_get_dealloc()(data);
        data = NULL;
    }

    return result;
}

static bool _RSA_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    EVP_PKEY *pkey = (EVP_PKEY *)jwk->keydata;

    BIGNUM *rsa_n = NULL, *rsa_e = NULL;
    _cjose_jwk_rsa_get(pkey, &rsa_n, &rsa_e, NULL);

    if (!_RSA_json_field(rsa_e, "e", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_n, "n", json, err))
    {
        return false;
    }

    if (rsa_n)
        BN_free(rsa_n);
    if (rsa_e)
        BN_free(rsa_e);

    return true;
}

static bool _RSA_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    EVP_PKEY *pkey = (EVP_PKEY *)jwk->keydata;

    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL;
    _cjose_jwk_rsa_get(pkey, &rsa_n, &rsa_e, &rsa_d);

    BIGNUM *rsa_p = NULL, *rsa_q = NULL;
    _cjose_jwk_rsa_get_factors(pkey, &rsa_p, &rsa_q);

    BIGNUM *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;
    _cjose_jwk_rsa_get_crt(pkey, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

    if (!_RSA_json_field(rsa_d, "d", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_p, "p", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_q, "q", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_dmp1, "dp", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_dmq1, "dq", json, err))
    {
        return false;
    }
    if (!_RSA_json_field(rsa_iqmp, "qi", json, err))
    {
        return false;
    }

    if (rsa_n)
        BN_free(rsa_n);
    if (rsa_e)
        BN_free(rsa_e);
    if (rsa_d)
        BN_free(rsa_d);

    if (rsa_p)
        BN_free(rsa_p);
    if (rsa_q)
        BN_free(rsa_q);

    if (rsa_dmp1)
        BN_free(rsa_dmp1);
    if (rsa_dmq1)
        BN_free(rsa_dmq1);
    if (rsa_iqmp)
        BN_free(rsa_iqmp);

    return true;
}

// interface functions -- RSA
static const uint8_t *DEFAULT_E_DAT = (const uint8_t *)"\x01\x00\x01";
static const size_t DEFAULT_E_LEN = 3;

cjose_jwk_t *cjose_jwk_create_RSA_random(size_t keysize, const uint8_t *e, size_t elen, cjose_err *err)
{
    cjose_jwk_t *rv = NULL;
    EVP_PKEY *rsa = NULL;
    BIGNUM *bn = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (0 == keysize)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_RSA_random_cleanup;
    }
    if (NULL == e || 0 >= elen)
    {
        e = DEFAULT_E_DAT;
        elen = DEFAULT_E_LEN;
    }

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    bn = BN_bin2bn(e, elen, NULL);
    if (bn == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_RSA_E, bn) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }
    if (OSSL_PARAM_BLD_push_uint(param_bld, OSSL_PKEY_PARAM_RSA_BITS, keysize) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    if (EVP_PKEY_keygen(ctx, &rsa) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_random_cleanup;
    }

    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_random_cleanup;
    }

    rv = _RSA_new(rsa, err);

create_RSA_random_cleanup:

    if (params)
    {
        OSSL_PARAM_free(params);
    }
    if (param_bld)
    {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (bn)
    {
        BN_free(bn);
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return rv;
}

#define _CJOSE_JWK_RSA_BIGNUM(bn, p, plen, key)                 \
    if (NULL != p && 0 < plen)                                  \
    {                                                           \
        bn = BN_bin2bn(p, plen, NULL);                          \
        if (!bn)                                                \
        {                                                       \
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);              \
            goto create_RSA_spec_cleanup;                       \
        }                                                       \
        if (OSSL_PARAM_BLD_push_BN(params_build, key, bn) != 1) \
        {                                                       \
            CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);              \
            goto create_RSA_spec_cleanup;                       \
        }                                                       \
    }

#define _CJOSE_JWK_RSA_BIGNUM_FREE(bn) \
    if (bn)                            \
    {                                  \
        BN_free(bn);                   \
    }

cjose_jwk_t *cjose_jwk_create_RSA_spec(const cjose_jwk_rsa_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *rv = NULL;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_e = NULL;
    BIGNUM *bn_d = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    BIGNUM *bn_dp = NULL;
    BIGNUM *bn_dq = NULL;
    BIGNUM *bn_qi = NULL;
    OSSL_PARAM_BLD *params_build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *rsa = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (NULL == spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPub = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->e && 0 < spec->elen);
    bool hasPriv = (NULL != spec->n && 0 < spec->nlen) && (NULL != spec->d && 0 < spec->dlen);
    if (!hasPub && !hasPriv)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_spec_cleanup;
    }

    params_build = OSSL_PARAM_BLD_new();
    if (params_build == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_spec_cleanup;
    }

    _CJOSE_JWK_RSA_BIGNUM(bn_n, spec->n, spec->nlen, OSSL_PKEY_PARAM_RSA_N);
    _CJOSE_JWK_RSA_BIGNUM(bn_e, spec->e, spec->elen, OSSL_PKEY_PARAM_RSA_E);

    if (hasPriv)
    {
        _CJOSE_JWK_RSA_BIGNUM(bn_d, spec->d, spec->dlen, OSSL_PKEY_PARAM_RSA_D);
        _CJOSE_JWK_RSA_BIGNUM(bn_p, spec->p, spec->plen, OSSL_PKEY_PARAM_RSA_FACTOR1);
        _CJOSE_JWK_RSA_BIGNUM(bn_q, spec->q, spec->qlen, OSSL_PKEY_PARAM_RSA_FACTOR2);
        _CJOSE_JWK_RSA_BIGNUM(bn_dp, spec->dp, spec->dplen, OSSL_PKEY_PARAM_RSA_EXPONENT1);
        _CJOSE_JWK_RSA_BIGNUM(bn_dq, spec->dq, spec->dqlen, OSSL_PKEY_PARAM_RSA_EXPONENT2);
        _CJOSE_JWK_RSA_BIGNUM(bn_qi, spec->qi, spec->qilen, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
    }

    params = OSSL_PARAM_BLD_to_param(params_build);
    if (params == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_spec_cleanup;
    }

    if (EVP_PKEY_fromdata(ctx, &rsa, hasPriv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_RSA_spec_cleanup;
    }

    if (!rsa)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_RSA_spec_cleanup;
    }

    rv = _RSA_new(rsa, err);

create_RSA_spec_cleanup:

    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (params_build)
    {
        OSSL_PARAM_BLD_free(params_build);
    }
    if (params)
    {
        OSSL_PARAM_free(params);
    }
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_n);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_e);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_d);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_p);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_q);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_dq);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_dp);
    _CJOSE_JWK_RSA_BIGNUM_FREE(bn_qi);

    return rv;
}

//////////////// Octet (Asymmetric) Key ////////////////
// internal data & functions -- Octet (Asymmetric) Key

static void _OKP_free(cjose_jwk_t *jwk);
static bool _OKP_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);
static bool _OKP_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err);

static const key_fntable OKP_FNTABLE = { _OKP_free, _OKP_public_fields, _OKP_private_fields };

static inline uint8_t _okp_size_for_curve(cjose_jwk_okp_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return 32;
    case CJOSE_JWK_OKP_ED448:
        return 57;
    case CJOSE_JWK_OKP_X25519:
        return 32;
    case CJOSE_JWK_OKP_X448:
        return 56;
    case CJOSE_JWK_EC_INVALID:
        return 0;
    }

    return 0;
}

static inline const char *_okp_name_for_curve(cjose_jwk_okp_curve crv, cjose_err *err)
{
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        return CJOSE_JWK_OKP_ED25519_STR;
    case CJOSE_JWK_OKP_ED448:
        return CJOSE_JWK_OKP_ED448_STR;
    case CJOSE_JWK_OKP_X25519:
        return CJOSE_JWK_OKP_X25519_STR;
    case CJOSE_JWK_OKP_X448:
        return CJOSE_JWK_OKP_X448_STR;
    case CJOSE_JWK_EC_INVALID:
        return NULL;
    }

    return NULL;
}

static inline bool _okp_curve_from_name(const char *name, cjose_jwk_okp_curve *crv, cjose_err *err)
{
    bool retval = true;
    if (strncmp(name, CJOSE_JWK_OKP_ED25519_STR, sizeof(CJOSE_JWK_OKP_ED25519_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_ED25519;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_ED448_STR, sizeof(CJOSE_JWK_OKP_ED448_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_ED448;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_X25519_STR, sizeof(CJOSE_JWK_OKP_X25519_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_X25519;
    }
    else if (strncmp(name, CJOSE_JWK_OKP_X448_STR, sizeof(CJOSE_JWK_OKP_X448_STR)) == 0)
    {
        *crv = CJOSE_JWK_OKP_X448;
    }
    else
    {
        retval = false;
    }
    return retval;
}

static cjose_jwk_t *_OKP_new(cjose_jwk_okp_curve crv, EVP_PKEY *okp, cjose_err *err)
{
    okp_keydata *keydata = cjose_get_alloc()(sizeof(okp_keydata));
    if (!keydata)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    keydata->crv = crv;
    keydata->key = okp;

    cjose_jwk_t *jwk = cjose_get_alloc()(sizeof(cjose_jwk_t));
    if (!jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        cjose_get_dealloc()(keydata);
        return NULL;
    }
    memset(jwk, 0, sizeof(cjose_jwk_t));
    jwk->retained = 1;
    jwk->kty = CJOSE_JWK_KTY_OKP;
    switch (crv)
    {
    case CJOSE_JWK_OKP_ED25519:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_OKP_ED448:
        jwk->keysize = 456;
        break;
    case CJOSE_JWK_OKP_X25519:
        jwk->keysize = 256;
        break;
    case CJOSE_JWK_OKP_X448:
        jwk->keysize = 448;
        break;
    case CJOSE_JWK_EC_INVALID:
        // should never happen
        jwk->keysize = 0;
        break;
    }
    jwk->keydata = keydata;
    jwk->fns = &OKP_FNTABLE;

    return jwk;
}

static void _OKP_free(cjose_jwk_t *jwk)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    jwk->keydata = NULL;

    if (keydata)
    {
        EVP_PKEY *okp = keydata->key;
        keydata->key = NULL;
        if (okp)
        {
            EVP_PKEY_free(okp);
        }
        cjose_get_dealloc()(keydata);
    }
    cjose_get_dealloc()(jwk);
}

static bool _OKP_public_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _okp_size_for_curve(keydata->crv, err);

    // output the curve
    field = json_string(_okp_name_for_curve(keydata->crv, err));
    if (!field)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "crv", field);
    json_decref(field);
    field = NULL;

    buffer = cjose_get_alloc()(numsize);

    if (EVP_PKEY_get_octet_string_param(keydata->key, OSSL_PKEY_PARAM_PUB_KEY, buffer, numsize, &len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _okp_to_string_cleanup;
    }

    // output the x coordinate
    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _okp_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "x", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_okp_to_string_cleanup:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
    }

    return result;
}

static bool _OKP_private_fields(const cjose_jwk_t *jwk, json_t *json, cjose_err *err)
{
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    uint8_t *buffer = NULL;
    char *b64u = NULL;
    size_t len = 0;
    json_t *field = NULL;
    bool result = false;

    // track expected binary data size
    uint8_t numsize = _okp_size_for_curve(keydata->crv, err);

    buffer = cjose_get_alloc()(numsize);
    if (!buffer)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _okp_to_string_cleanup;
    }

    EVP_PKEY_get_octet_string_param(keydata->key, OSSL_PKEY_PARAM_PRIV_KEY, buffer, numsize, &len);
    // short circuit if 'd' is NULL or 0
    if (!buffer || (len == 0))
    {
        return true;
    }

    if (!cjose_base64url_encode(buffer, numsize, &b64u, &len, err))
    {
        goto _okp_to_string_cleanup;
    }
    field = _cjose_json_stringn(b64u, len, err);
    if (!field)
    {
        goto _okp_to_string_cleanup;
    }
    json_object_set(json, "d", field);
    json_decref(field);
    field = NULL;
    cjose_get_dealloc()(b64u);
    b64u = NULL;

    result = true;

_okp_to_string_cleanup:
    if (buffer)
    {
        cjose_get_dealloc()(buffer);
    }
    if (b64u)
    {
        cjose_get_dealloc()(b64u);
    }
    return result;
}

// interface functions -- Octet (Asymmetric) Key

cjose_jwk_t *cjose_jwk_create_OKP_random(cjose_jwk_okp_curve crv, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *pkey = NULL;

    const char *curve = OBJ_nid2sn(crv);
    if (curve == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_OKP_failed;
    }

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, curve);
    if (pkey == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_failed;
    }

    jwk = _OKP_new(crv, pkey, err);
    if (!jwk)
    {
        goto create_OKP_failed;
    }

    return jwk;

create_OKP_failed:

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return NULL;
}

cjose_jwk_t *cjose_jwk_create_OKP_spec(const cjose_jwk_okp_keyspec *spec, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;

    if (!spec)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    bool hasPriv = (NULL != spec->d && 0 < spec->dlen);
    bool hasPub = ((NULL != spec->x && 0 < spec->xlen));
    if (!hasPriv && !hasPub)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    const char *curve = OBJ_nid2sn(spec->crv);
    if (curve == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto create_OKP_failed;
    }

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_failed;
    }

    if (hasPriv)
    {
        if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, spec->d, spec->dlen) != 1)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_OKP_failed;
        }
    }
    if (hasPub)
    {
        if (OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, spec->x, spec->xlen) != 1)
        {
            CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
            goto create_OKP_failed;
        }
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (params == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto create_OKP_failed;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, curve, NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_failed;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_failed;
    }

    if (EVP_PKEY_fromdata(
            ctx, &pkey,
            (hasPriv ? OSSL_KEYMGMT_SELECT_KEYPAIR : OSSL_KEYMGMT_SELECT_PUBLIC_KEY) | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
        != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto create_OKP_failed;
    }

    jwk = _OKP_new(spec->crv, pkey, err);
    if (!jwk)
    {
        goto create_OKP_failed;
    }

    // jump to cleanup
    goto create_OKP_cleanup;

create_OKP_failed:

    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

create_OKP_cleanup:

    if (param_bld)
    {
        OSSL_PARAM_BLD_free(param_bld);
    }
    if (params)
    {
        OSSL_PARAM_free(params);
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return jwk;
}

const cjose_jwk_okp_curve cjose_jwk_OKP_get_curve(const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jwk || CJOSE_JWK_KTY_OKP != cjose_jwk_get_kty(jwk, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return CJOSE_JWK_OKP_INVALID;
    }

    okp_keydata *keydata = jwk->keydata;
    return keydata->crv;
}

//////////////// Import ////////////////
// internal data & functions -- JWK key import

static const char *_get_json_object_string_attribute(json_t *json, const char *key, cjose_err *err)
{
    const char *attr_str = NULL;
    json_t *attr_json = json_object_get(json, key);
    if (NULL != attr_json)
    {
        attr_str = json_string_value(attr_json);
    }
    return attr_str;
}

/**
 * Internal helper function for extracing an octet string from a base64url
 * encoded field.  Caller provides the json object, the attribute key,
 * and an expected length for the octet string.  On successful decoding,
 * this will return a newly allocated buffer with the decoded octet string
 * of the expected length.
 *
 * Note: caller is responsible for freeing the buffer returned by this function.
 *
 * \param[in]     json the JSON object from which to read the attribute.
 * \param[in]     key the name of the attribute to be decoded.
 * \param[out]    pointer to buffer of octet string (if decoding succeeds).
 * \param[in/out] in as the expected length of the attribute, out as the
 *                actual decoded length.  Note, this method succeeds only
 *                if the actual decoded length matches the expected length.
 *                If the in-value is 0 this indicates there is no particular
 *                expected length (i.e. any length is ok).
 * \returns true  if attribute is either not present or successfully decoded.
 *                false otherwise.
 */
static bool
_decode_json_object_base64url_attribute(json_t *jwk_json, const char *key, uint8_t **buffer, size_t *buflen, cjose_err *err)
{
    // get the base64url encoded string value of the attribute (if any)
    const char *str = _get_json_object_string_attribute(jwk_json, key, err);
    if (str == NULL || strlen(str) == 0)
    {
        *buflen = 0;
        *buffer = NULL;
        return true;
    }

    // if a particular decoded length is expected, check for that
    if (*buflen != 0)
    {
        const char *end = NULL;
        for (end = str + strlen(str) - 1; *end == '=' && end > str; --end)
            ;
        size_t unpadded_len = end + 1 - str - ((*end == '=') ? 1 : 0);
        size_t expected_len = ceil(4 * ((float)*buflen / 3));

        if (expected_len != unpadded_len)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            *buflen = 0;
            *buffer = NULL;
            return false;
        }
    }

    // decode the base64url encoded string to the allocated buffer
    if (!cjose_base64url_decode(str, strlen(str), buffer, buflen, err))
    {
        *buflen = 0;
        *buffer = NULL;
        return false;
    }

    return true;
}

static cjose_jwk_t *_cjose_jwk_import_EC(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *y_buffer = NULL;
    uint8_t *d_buffer = NULL;

    // get the value of the crv attribute
    const char *crv_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the curve identifier for the curve named by crv
    cjose_jwk_ec_curve crv;
    if (!_ec_curve_from_name(crv_str, &crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the x coordinate
    size_t x_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the y coordinate
    size_t y_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Y_STR, &y_buffer, &y_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // get the decoded value of the private key d
    size_t d_buflen = (size_t)_ec_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_EC_cleanup;
    }

    // create an ec keyspec
    cjose_jwk_ec_keyspec ec_keyspec;
    memset(&ec_keyspec, 0, sizeof(cjose_jwk_ec_keyspec));
    ec_keyspec.crv = crv;
    ec_keyspec.x = x_buffer;
    ec_keyspec.xlen = x_buflen;
    ec_keyspec.y = y_buffer;
    ec_keyspec.ylen = y_buflen;
    ec_keyspec.d = d_buffer;
    ec_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_EC_spec(&ec_keyspec, err);

import_EC_cleanup:
    if (NULL != x_buffer)
    {
        cjose_get_dealloc()(x_buffer);
    }
    if (NULL != y_buffer)
    {
        cjose_get_dealloc()(y_buffer);
    }
    if (NULL != d_buffer)
    {
        cjose_get_dealloc()(d_buffer);
    }

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_RSA(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *n_buffer = NULL;
    uint8_t *e_buffer = NULL;
    uint8_t *d_buffer = NULL;
    uint8_t *p_buffer = NULL;
    uint8_t *q_buffer = NULL;
    uint8_t *dp_buffer = NULL;
    uint8_t *dq_buffer = NULL;
    uint8_t *qi_buffer = NULL;

    // get the decoded value of n (buflen = 0 means no particular expected len)
    size_t n_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_N_STR, &n_buffer, &n_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of e
    size_t e_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_E_STR, &e_buffer, &e_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of d
    size_t d_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of p
    size_t p_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_P_STR, &p_buffer, &p_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of q
    size_t q_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_Q_STR, &q_buffer, &q_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dp
    size_t dp_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DP_STR, &dp_buffer, &dp_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of dq
    size_t dq_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_DQ_STR, &dq_buffer, &dq_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // get the decoded value of qi
    size_t qi_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_QI_STR, &qi_buffer, &qi_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_RSA_cleanup;
    }

    // create an rsa keyspec
    cjose_jwk_rsa_keyspec rsa_keyspec;
    memset(&rsa_keyspec, 0, sizeof(cjose_jwk_rsa_keyspec));
    rsa_keyspec.n = n_buffer;
    rsa_keyspec.nlen = n_buflen;
    rsa_keyspec.e = e_buffer;
    rsa_keyspec.elen = e_buflen;
    rsa_keyspec.d = d_buffer;
    rsa_keyspec.dlen = d_buflen;
    rsa_keyspec.p = p_buffer;
    rsa_keyspec.plen = p_buflen;
    rsa_keyspec.q = q_buffer;
    rsa_keyspec.qlen = q_buflen;
    rsa_keyspec.dp = dp_buffer;
    rsa_keyspec.dplen = dp_buflen;
    rsa_keyspec.dq = dq_buffer;
    rsa_keyspec.dqlen = dq_buflen;
    rsa_keyspec.qi = qi_buffer;
    rsa_keyspec.qilen = qi_buflen;

    // create the jwk
    jwk = cjose_jwk_create_RSA_spec(&rsa_keyspec, err);

import_RSA_cleanup:
    cjose_get_dealloc()(n_buffer);
    cjose_get_dealloc()(e_buffer);
    cjose_get_dealloc()(d_buffer);
    cjose_get_dealloc()(p_buffer);
    cjose_get_dealloc()(q_buffer);
    cjose_get_dealloc()(dp_buffer);
    cjose_get_dealloc()(dq_buffer);
    cjose_get_dealloc()(qi_buffer);

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_oct(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *k_buffer = NULL;

    // get the decoded value of k (buflen = 0 means no particular expected len)
    size_t k_buflen = 0;
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_K_STR, &k_buffer, &k_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_oct_cleanup;
    }

    // create the jwk
    jwk = cjose_jwk_create_oct_spec(k_buffer, k_buflen, err);

import_oct_cleanup:
    if (NULL != k_buffer)
    {
        cjose_get_dealloc()(k_buffer);
    }

    return jwk;
}

static cjose_jwk_t *_cjose_jwk_import_OKP(json_t *jwk_json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;
    uint8_t *x_buffer = NULL;
    uint8_t *d_buffer = NULL;

    // get the value of the crv attribute
    const char *crv_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_CRV_STR, err);
    if (crv_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the curve identifier for the curve named by crv
    cjose_jwk_okp_curve crv;
    if (!_okp_curve_from_name(crv_str, &crv, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the decoded value of the x coordinate
    size_t x_buflen = (size_t)_okp_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_X_STR, &x_buffer, &x_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // get the decoded value of the private key d
    size_t d_buflen = (size_t)_okp_size_for_curve(crv, err);
    if (!_decode_json_object_base64url_attribute(jwk_json, CJOSE_JWK_D_STR, &d_buffer, &d_buflen, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_OKP_cleanup;
    }

    // create an Octet Asymmetric Key keyspec
    cjose_jwk_okp_keyspec okp_keyspec;
    memset(&okp_keyspec, 0, sizeof(cjose_jwk_okp_keyspec));
    okp_keyspec.crv = crv;
    okp_keyspec.x = x_buffer;
    okp_keyspec.xlen = x_buflen;
    okp_keyspec.d = d_buffer;
    okp_keyspec.dlen = d_buflen;

    // create the jwk
    jwk = cjose_jwk_create_OKP_spec(&okp_keyspec, err);

import_OKP_cleanup:
    if (NULL != x_buffer)
    {
        cjose_get_dealloc()(x_buffer);
    }
    if (NULL != d_buffer)
    {
        cjose_get_dealloc()(d_buffer);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import(const char *jwk_str, size_t len, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    // check params
    if ((NULL == jwk_str) || (0 == len))
    {
        return NULL;
    }

    // parse json content from the given string
    json_t *jwk_json = json_loadb(jwk_str, len, 0, NULL);
    if (NULL == jwk_json)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto import_cleanup;
    }

    jwk = cjose_jwk_import_json((cjose_header_t *)jwk_json, err);

// poor man's "finally"
import_cleanup:
    if (NULL != jwk_json)
    {
        json_decref(jwk_json);
    }

    return jwk;
}

cjose_jwk_t *cjose_jwk_import_json(cjose_header_t *json, cjose_err *err)
{
    cjose_jwk_t *jwk = NULL;

    json_t *jwk_json = (json_t *)json;

    if (NULL == jwk_json || JSON_OBJECT != json_typeof(jwk_json))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get the string value of the kty attribute of the jwk
    const char *kty_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KTY_STR, err);
    if (NULL == kty_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // get kty corresponding to kty_str (kty is required)
    cjose_jwk_kty_t kty;
    if (!_kty_from_name(kty_str, &kty, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // create a cjose_jwt_t based on the kty
    switch (kty)
    {
    case CJOSE_JWK_KTY_EC:
        jwk = _cjose_jwk_import_EC(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_RSA:
        jwk = _cjose_jwk_import_RSA(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_OCT:
        jwk = _cjose_jwk_import_oct(jwk_json, err);
        break;

    case CJOSE_JWK_KTY_OKP:
        jwk = _cjose_jwk_import_OKP(jwk_json, err);
        break;

    default:
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }
    if (NULL == jwk)
    {
        // helper function will have already set err
        return NULL;
    }

    // get the value of the kid attribute (kid is optional)
    const char *kid_str = _get_json_object_string_attribute(jwk_json, CJOSE_JWK_KID_STR, err);
    if (kid_str != NULL)
    {
        jwk->kid = _cjose_strndup(kid_str, -1, err);
        if (!jwk->kid)
        {
            cjose_jwk_release(jwk);
            return NULL;
        }
    }

    return jwk;
}

//////////////// ECDH ////////////////
// internal data & functions -- ECDH derivation

static bool _cjose_jwk_evp_key_from_ec_key(const cjose_jwk_t *jwk, EVP_PKEY **key, cjose_err *err)
{
    // validate that the jwk is of type EC and we have a valid out-param
    if (NULL == jwk || CJOSE_JWK_KTY_EC != jwk->kty || NULL == jwk->keydata || NULL == key || NULL != *key)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // obtain the EVP_PKEY (EC_KEY)
    *key = EVP_PKEY_dup(((struct _ec_keydata_int *)(jwk->keydata))->key);
    if (*key == NULL)
    {
        return false;
    }

    return true;
}

cjose_jwk_t *cjose_jwk_derive_ecdh_secret(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    return cjose_jwk_derive_ecdh_ephemeral_key(jwk_self, jwk_peer, salt, salt_len, err);
}

cjose_jwk_t *cjose_jwk_derive_ecdh_ephemeral_key(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, const uint8_t *salt, size_t salt_len, cjose_err *err)
{
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    uint8_t *ephemeral_key = NULL;
    size_t ephemeral_key_len = 0;
    cjose_jwk_t *jwk_ephemeral_key = NULL;

    if (!cjose_jwk_derive_ecdh_bits(jwk_self, jwk_peer, &secret, &secret_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // HKDF of the DH shared secret (SHA256, no info, 256 bit expand)
    ephemeral_key_len = 32;
    ephemeral_key = (uint8_t *)cjose_get_alloc()(ephemeral_key_len);
    if (!cjose_jwk_hkdf(EVP_sha256(), salt, salt_len, (uint8_t *)"", 0, secret, secret_len, ephemeral_key, ephemeral_key_len, err))
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // create a JWK of the shared secret
    jwk_ephemeral_key = cjose_jwk_create_oct_spec(ephemeral_key, ephemeral_key_len, err);
    if (NULL == jwk_ephemeral_key)
    {
        goto _cjose_jwk_derive_shared_secret_fail;
    }

    // happy path
    cjose_get_dealloc()(secret);
    cjose_get_dealloc()(ephemeral_key);

    return jwk_ephemeral_key;

// fail path
_cjose_jwk_derive_shared_secret_fail:

    cjose_get_dealloc()(secret);
    cjose_get_dealloc()(ephemeral_key);

    return NULL;
}

bool cjose_jwk_derive_ecdh_bits(
    const cjose_jwk_t *jwk_self, const cjose_jwk_t *jwk_peer, uint8_t **output, size_t *output_len, cjose_err *err)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_self = NULL;
    EVP_PKEY *pkey_peer = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;

    // get EVP_KEY from jwk_self
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_self, &pkey_self, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // get EVP_KEY from jwk_peer
    if (!_cjose_jwk_evp_key_from_ec_key(jwk_peer, &pkey_peer, err))
    {
        goto _cjose_jwk_derive_bits_fail;
    }

    // create derivation context based on local key pair
    ctx = EVP_PKEY_CTX_new(pkey_self, NULL);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // initialize derivation context
    if (1 != EVP_PKEY_derive_init(ctx))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // provide the peer public key
    if (1 != EVP_PKEY_derive_set_peer(ctx, pkey_peer))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jwk_derive_bits_fail;
    }

    // allocate buffer for shared secret
    secret = (uint8_t *)cjose_get_alloc()(secret_len);
    if (NULL == output)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_bits_fail;
    }
    memset(secret, 0, secret_len);

    // derive the shared secret
    if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jwk_derive_bits_fail;
    }

    // happy path
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey_self);
    EVP_PKEY_free(pkey_peer);

    *output = secret;
    *output_len = secret_len;
    return true;

_cjose_jwk_derive_bits_fail:

    if (NULL != ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (NULL != pkey_self)
    {
        EVP_PKEY_free(pkey_self);
    }
    if (NULL != pkey_peer)
    {
        EVP_PKEY_free(pkey_peer);
    }
    cjose_get_dealloc()(secret);

    return false;
}

bool cjose_jwk_hkdf(const EVP_MD *md,
                    const uint8_t *salt,
                    size_t salt_len,
                    const uint8_t *info,
                    size_t info_len,
                    const uint8_t *ikm,
                    size_t ikm_len,
                    uint8_t *okm,
                    unsigned int okm_len,
                    cjose_err *err)
{
    // current impl. is very limited: SHA256, 256 bit output, and no info
    if ((EVP_sha256() != md) || (0 != info_len) || (32 != okm_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // HKDF-Extract, HMAC-SHA256(salt, IKM) -> PRK
    unsigned int prk_len;
    unsigned char prk[EVP_MAX_MD_SIZE];
    if (NULL == HMAC(md, salt, salt_len, ikm, ikm_len, prk, &prk_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    // HKDF-Expand, HMAC-SHA256(PRK,0x01) -> OKM
    const unsigned char t[] = { 0x01 };
    if (NULL == HMAC(md, prk, prk_len, t, sizeof(t), okm, NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}
