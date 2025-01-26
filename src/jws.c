/*!
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2014-2016 Cisco Systems, Inc.  All Rights Reserved.
 */

#include <cjose/base64.h>
#include <cjose/header.h>
#include <cjose/jws.h>
#include <cjose/jwk.h>
#include <cjose/util.h>

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>

#include "include/jwk_int.h"
#include "include/header_int.h"
#include "include/jws_int.h"

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_dig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_hdr(cjose_jws_t *jws, cjose_header_t *header, cjose_err *err)
{
    // save header object as part of the JWS (and incr. refcount)
    jws->hdr = (json_t *)header;
    json_incref(jws->hdr);

    // base64url encode the header
    char *hdr_str = json_dumps(jws->hdr, JSON_ENCODE_ANY | JSON_PRESERVE_ORDER | JSON_COMPACT);
    if (NULL == hdr_str)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    if (!cjose_base64url_encode((const uint8_t *)hdr_str, strlen(hdr_str), &jws->hdr_b64u, &jws->hdr_b64u_len, err))
    {
        cjose_get_dealloc()(hdr_str);
        return false;
    }
    cjose_get_dealloc()(hdr_str);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_validate_hdr(cjose_jws_t *jws, cjose_err *err)
{
    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if ((NULL == alg_obj) || (!json_is_string(alg_obj)))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    if ((strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_ps;
        jws->fns.verify = _cjose_jws_verify_sig_ps;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_RS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_rs;
        jws->fns.verify = _cjose_jws_verify_sig_rs;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_HS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_hmac_sha;
        jws->fns.sign = _cjose_jws_build_sig_hmac_sha;
        jws->fns.verify = _cjose_jws_verify_sig_hmac_sha;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_sha;
        jws->fns.sign = _cjose_jws_build_sig_ec;
        jws->fns.verify = _cjose_jws_verify_sig_ec;
    }
    else
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dat(cjose_jws_t *jws, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err)
{
    // copy plaintext data
    jws->dat_len = plaintext_len;
    jws->dat = (uint8_t *)cjose_get_alloc()(jws->dat_len);
    if (NULL == jws->dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    memcpy(jws->dat, plaintext, jws->dat_len);

    // base64url encode data
    if (!cjose_base64url_encode((const uint8_t *)plaintext, plaintext_len, &jws->dat_b64u, &jws->dat_b64u_len, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    const EVP_MD *digest_alg = NULL;
    if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0))
        digest_alg = EVP_sha256();
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0))
        digest_alg = EVP_sha384();
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0))
        digest_alg = EVP_sha512();

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    if (NULL != jws->dig)
    {
        cjose_get_dealloc()(jws->dig);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(digest_alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // instantiate and initialize a new mac digest context
    ctx = EVP_MD_CTX_create();
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    EVP_MD_CTX_init(ctx);

    // create digest as DIGEST(B64U(HEADER).B64U(DATA))
    if (EVP_DigestInit_ex(ctx, digest_alg, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->hdr_b64u, jws->hdr_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, ".", 1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestUpdate(ctx, jws->dat_b64u, jws->dat_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }
    if (EVP_DigestFinal_ex(ctx, jws->dig, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_build_dig_sha_cleanup:
    if (NULL != ctx)
    {
        EVP_MD_CTX_destroy(ctx);
    }

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    const EVP_MD *digest_alg = NULL;
    char *digest_str = NULL;
    if (strcmp(alg, CJOSE_HDR_ALG_HS256) == 0)
    {
        digest_alg = EVP_sha256();
        digest_str = "SHA256";
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0)
    {
        digest_alg = EVP_sha384();
        digest_str = "SHA384";
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0)
    {
        digest_alg = EVP_sha512();
        digest_str = "SHA512";
    }

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    if (NULL != jws->dig)
    {
        cjose_get_dealloc()(jws->dig);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(digest_alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (NULL == jws->dig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    // instantiate and initialize a new mac digest context
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (NULL == mac)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (NULL == ctx)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    OSSL_PARAM params[4], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, digest_str, 0);
    *p = OSSL_PARAM_construct_end();

    // create digest as DIGEST(B64U(HEADER).B64U(DATA))
    if (EVP_MAC_init(ctx, jwk->keydata, jwk->keysize / 8, params) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)jws->hdr_b64u, jws->hdr_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)".", 1) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_update(ctx, (const unsigned char *)jws->dat_b64u, jws->dat_b64u_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }
    if (EVP_MAC_final(ctx, jws->dig, NULL, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_build_dig_hmac_sha_cleanup:
    if (NULL != ctx)
    {
        EVP_MAC_CTX_free(ctx);
    }

    if (NULL != mac)
    {
        EVP_MAC_free(mac);
    }

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_rsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, int padding, cjose_err *err)
{
    bool rv = false;
    EVP_PKEY_CTX *ctx = NULL;
    const char *alg = NULL;
    const EVP_MD *digest_alg = NULL;

    // ensure jwk is private RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // allocate buffer for signature
    jws->sig_len = EVP_PKEY_size((EVP_PKEY *)jwk->keydata);
    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0))
    {
        digest_alg = EVP_sha256();
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0))
    {
        digest_alg = EVP_sha384();
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0))
    {
        digest_alg = EVP_sha512();
    }

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)jwk->keydata, NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (EVP_PKEY_sign_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    // NB: CJOSE_ERR_INVALID_ARG to satisfy 326test_cjose_jws_sign_with_bad_key check_jws.c
    if (EVP_PKEY_private_check(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (EVP_PKEY_sign(ctx, jws->sig, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    rv = true;

_cjose_jws_build_sig_rsa_cleanup:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return rv;
}

static bool _cjose_jws_build_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    return _cjose_jws_build_sig_rsa(jws, jwk, RSA_PKCS1_PSS_PADDING, err);
}

static bool _cjose_jws_build_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    return _cjose_jws_build_sig_rsa(jws, jwk, RSA_PKCS1_PADDING, err);
}

static bool _cjose_jws_build_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    // ensure jwk is OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // allocate buffer for signature
    jws->sig_len = jws->dig_len;
    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    memcpy(jws->sig, jws->dig, jws->sig_len);

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EVP_PKEY_CTX *ctx = NULL;
    const char *alg = NULL;
    const EVP_MD *digest_alg = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;

    // ensure jwk is EC
    if (jwk->kty != CJOSE_JWK_KTY_EC)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    if (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0)
    {
        digest_alg = EVP_sha256();
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0)
    {
        digest_alg = EVP_sha384();
    }
    else if (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0)
    {
        digest_alg = EVP_sha512();
    }

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)keydata->key, NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    if (EVP_PKEY_sign_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    if (EVP_PKEY_sign(ctx, NULL, &sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    sig = (unsigned char *)cjose_get_alloc()(sig_len);
    if (NULL == sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ec_cleanup;
    }
    memset(sig, 0, sig_len);

    if (EVP_PKEY_sign(ctx, sig, &sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    jws->sig = sig;
    jws->sig_len = sig_len;

    // allocate buffer for signature
    switch (keydata->crv)
    {
    case CJOSE_JWK_EC_P_256:
        jws->sig_len = 32 * 2;
        break;
    case CJOSE_JWK_EC_P_384:
        jws->sig_len = 48 * 2;
        break;
    case CJOSE_JWK_EC_P_521:
        jws->sig_len = 66 * 2;
        break;
    case CJOSE_JWK_EC_INVALID:
        jws->sig_len = 0;
        break;
    }

    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (NULL == jws->sig)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    memset(jws->sig, 0, jws->sig_len);

    const unsigned char *p = sig;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (ecdsa_sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    const BIGNUM *pr, *ps;
    ECDSA_SIG_get0(ecdsa_sig, &pr, &ps);
    int rlen = BN_num_bytes(pr);
    int slen = BN_num_bytes(ps);
    BN_bn2bin(pr, jws->sig + jws->sig_len / 2 - rlen);
    BN_bn2bin(ps, jws->sig + jws->sig_len - slen);

    // base64url encode signed digest
    if (!cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    retval = true;

_cjose_jws_build_sig_ec_cleanup:

    if (ecdsa_sig)
    {
        ECDSA_SIG_free(ecdsa_sig);
    }
    if (sig)
    {
        cjose_get_dealloc()(sig);
    }
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_cser(cjose_jws_t *jws, cjose_err *err)
{
    // both sign and import should be setting these - but check just in case
    if (NULL == jws->hdr_b64u || NULL == jws->dat_b64u || NULL == jws->sig_b64u)
    {
        return false;
    }

    // compute length of compact serialization
    jws->cser_len = jws->hdr_b64u_len + jws->dat_b64u_len + jws->sig_b64u_len + 3;

    if (NULL != jws->cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
        return false;
    }

    // allocate buffer for compact serialization
    jws->cser = (char *)cjose_get_alloc()(jws->cser_len);
    if (NULL == jws->cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    // build the compact serialization
    snprintf(jws->cser, jws->cser_len, "%s.%s.%s", jws->hdr_b64u, jws->dat_b64u, jws->sig_b64u);

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_sign(
    const cjose_jwk_t *jwk, cjose_header_t *protected_header, const uint8_t *plaintext, size_t plaintext_len, cjose_err *err)
{
    cjose_jws_t *jws = NULL;

    if (NULL == jwk || NULL == protected_header || NULL == plaintext)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize JWS
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // build JWS header
    if (!_cjose_jws_build_hdr(jws, protected_header, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build the JWS data segment
    if (!_cjose_jws_build_dat(jws, plaintext, plaintext_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS digest (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // sign the JWS digest
    if (!jws->fns.sign(jws, jwk, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS compact serialization
    if (!_cjose_jws_build_cser(jws, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}

////////////////////////////////////////////////////////////////////////////////
void cjose_jws_release(cjose_jws_t *jws)
{
    if (NULL == jws)
    {
        return;
    }

    if (NULL != jws->hdr)
    {
        json_decref(jws->hdr);
    }

    cjose_get_dealloc()(jws->hdr_b64u);
    cjose_get_dealloc()(jws->dat);
    cjose_get_dealloc()(jws->dat_b64u);
    cjose_get_dealloc()(jws->dig);
    cjose_get_dealloc()(jws->sig);
    cjose_get_dealloc()(jws->sig_b64u);
    cjose_get_dealloc()(jws->cser);
    cjose_get_dealloc()(jws);
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_export(cjose_jws_t *jws, const char **compact, cjose_err *err)
{
    if (NULL == jws || NULL == compact)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (NULL == jws->cser)
    {
        _cjose_jws_build_cser(jws, err);
    }

    *compact = jws->cser;
    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_strcpy(char **dst, const char *src, int len, cjose_err *err)
{
    if (NULL == dst)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    *dst = (char *)cjose_get_alloc()(len + 1);
    if (NULL == *dst)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    strncpy(*dst, src, len);
    (*dst)[len] = 0;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_jws_t *cjose_jws_import(const char *cser, size_t cser_len, cjose_err *err)
{
    cjose_jws_t *jws = NULL;
    size_t len = 0;

    if (NULL == cser)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize a new JWS object
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (NULL == jws)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // find the indexes of the dots
    int idx = 0;
    int d[2] = { 0, 0 };
    for (int i = 0; i < cser_len && idx < 2; ++i)
    {
        if (cser[i] == '.')
        {
            d[idx++] = i;
        }
    }

    // fail if we didn't find both dots
    if (0 == d[1])
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and decode header b64u segment
    uint8_t *hdr_str = NULL;
    jws->hdr_b64u_len = d[0];
    _cjose_jws_strcpy(&jws->hdr_b64u, cser, jws->hdr_b64u_len, err);
    if (!cjose_base64url_decode(jws->hdr_b64u, jws->hdr_b64u_len, &hdr_str, &len, err) || NULL == hdr_str)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // deserialize JSON header
    jws->hdr = json_loadb((const char *)hdr_str, len, 0, NULL);
    cjose_get_dealloc()(hdr_str);
    if (NULL == jws->hdr)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        cjose_jws_release(jws);
        return NULL;
    }

    // validate the JSON header segment
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        // make an exception for alg=none so that it will import/parse but not sign/verify
        json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
        if (NULL == alg_obj)
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            cjose_jws_release(jws);
            return NULL;
        }
        const char *alg = json_string_value(alg_obj);
        if ((!alg) || (strcmp(alg, CJOSE_HDR_ALG_NONE) != 0))
        {
            CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
            cjose_jws_release(jws);
            return NULL;
        }
    }

    // copy and b64u decode data segment
    jws->dat_b64u_len = d[1] - d[0] - 1;
    _cjose_jws_strcpy(&jws->dat_b64u, cser + d[0] + 1, jws->dat_b64u_len, err);
    if (!cjose_base64url_decode(jws->dat_b64u, jws->dat_b64u_len, &jws->dat, &jws->dat_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // copy and b64u decode signature segment
    jws->sig_b64u_len = cser_len - d[1] - 1;
    _cjose_jws_strcpy(&jws->sig_b64u, cser + d[1] + 1, jws->sig_b64u_len, err);
    if (!cjose_base64url_decode(jws->sig_b64u, jws->sig_b64u_len, &jws->sig, &jws->sig_len, err))
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_rsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, int padding, cjose_err *err)
{
    bool retval = false;
    EVP_PKEY_CTX *ctx = NULL;
    const char *alg = NULL;
    const EVP_MD *digest_alg = NULL;

    // ensure jwk is RSA
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    // make sure we have an alg header
    json_t *alg_obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (NULL == alg_obj)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    alg = json_string_value(alg_obj);

    // build digest using SHA-256/384/512 digest algorithm
    if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0))
    {
        digest_alg = EVP_sha256();
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0))
    {
        digest_alg = EVP_sha384();
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0))
    {
        digest_alg = EVP_sha512();
    }

    if (NULL == digest_alg)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)jwk->keydata, NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    if (EVP_PKEY_verify_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, digest_alg) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    if (EVP_PKEY_verify(ctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_rsa_cleanup:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return retval;
}

static bool _cjose_jws_verify_sig_ps(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    return _cjose_jws_verify_sig_rsa(jws, jwk, RSA_PKCS1_PSS_PADDING, err);
}

static bool _cjose_jws_verify_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    return _cjose_jws_verify_sig_rsa(jws, jwk, RSA_PKCS1_PADDING, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;

    // ensure jwk is OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_hmac_sha_cleanup;
    }

    // verify decrypted digest matches computed digest
    if ((cjose_const_memcmp(jws->dig, jws->sig, jws->dig_len) != 0) || (jws->sig_len != jws->dig_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_hmac_sha_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_hmac_sha_cleanup:

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EVP_PKEY_CTX *ctx = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    unsigned char *der_sig = NULL;
    //    const char *alg = NULL;
    //    const EVP_MD *digest_alg = NULL;

    // ensure jwk is EC
    if (jwk->kty != CJOSE_JWK_KTY_EC)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)keydata->key, NULL);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }

    if (EVP_PKEY_verify_init(ctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }
    int key_len = jws->sig_len / 2;

    BIGNUM *pr = BN_new(), *ps = BN_new();
    BN_bin2bn(jws->sig, key_len, pr);
    BN_bin2bn(jws->sig + key_len, key_len, ps);
    ECDSA_SIG_set0(ecdsa_sig, pr, ps);

    int der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    der_sig = cjose_get_alloc()(der_sig_len);
    unsigned char *p1 = der_sig;
    der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &p1);

    if (EVP_PKEY_verify(ctx, der_sig, der_sig_len, jws->dig, jws->dig_len) < 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_ec_cleanup;
    }

    // if we got this far - success
    retval = true;

_cjose_jws_verify_sig_ec_cleanup:

    if (der_sig)
    {
        cjose_get_dealloc()(der_sig);
    }
    if (ecdsa_sig)
    {
        ECDSA_SIG_free(ecdsa_sig);
    }
    if (ctx != NULL)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_verify(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (NULL == jws || NULL == jwk)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // validate JWS header
    if (!_cjose_jws_validate_hdr(jws, err))
    {
        return false;
    }

    // build JWS digest from header and payload (hashed signing input value)
    if (!jws->fns.digest(jws, jwk, err))
    {
        return false;
    }

    // verify JWS signature
    if (!jws->fns.verify(jws, jwk, err))
    {
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_get_plaintext(const cjose_jws_t *jws, uint8_t **plaintext, size_t *plaintext_len, cjose_err *err)
{
    if (NULL == jws || NULL == plaintext || NULL == jws->dat)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    *plaintext = jws->dat;
    *plaintext_len = jws->dat_len;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
cjose_header_t *cjose_jws_get_protected(cjose_jws_t *jws)
{
    if (NULL == jws)
    {
        return NULL;
    }

    return (cjose_header_t *)jws->hdr;
}
