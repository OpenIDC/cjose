/*!
 * Copyrights
 *
 * Portions created or assigned to ZmartZone Holding B.V. are
 * Copyright (c) 2018-2025 ZmartZone Holding B.V.  All Rights Reserved.
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

static bool _cjose_jws_build_dig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_dig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_dig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_build_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

static bool _cjose_jws_verify_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err);

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_hdr(cjose_jws_t *jws, cjose_header_t *header, cjose_err *err)
{
    // save header object as part of the JWS (and incr. refcount)
    jws->hdr = (json_t *)header;
    json_incref(jws->hdr);

    // base64url encode the header
    char *hdr_str = json_dumps(jws->hdr, JSON_ENCODE_ANY | JSON_PRESERVE_ORDER | JSON_COMPACT);
    if (hdr_str == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    if (cjose_base64url_encode((const uint8_t *)hdr_str, strlen(hdr_str), &jws->hdr_b64u, &jws->hdr_b64u_len, err) == false)
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
    json_t *obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if ((obj == NULL) || (json_is_string(obj) == 0))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    const char *alg = json_string_value(obj);

    if ((strcmp(alg, CJOSE_HDR_ALG_PS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_rs;
        jws->fns.sign = _cjose_jws_build_sig_ps;
        jws->fns.verify = _cjose_jws_verify_sig_ps;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_RS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_RS512) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_rs;
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
        jws->fns.digest = _cjose_jws_build_dig_ec;
        jws->fns.sign = _cjose_jws_build_sig_ec;
        jws->fns.verify = _cjose_jws_verify_sig_ec;
    }
    else if ((strcmp(alg, CJOSE_HDR_ALG_EdDSA) == 0))
    {
        jws->fns.digest = _cjose_jws_build_dig_eddsa;
        jws->fns.sign = _cjose_jws_build_sig_eddsa;
        jws->fns.verify = _cjose_jws_verify_sig_eddsa;
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
    if (jws->dat == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    memcpy(jws->dat, plaintext, jws->dat_len);

    // base64url encode data
    return cjose_base64url_encode((const uint8_t *)plaintext, plaintext_len, &jws->dat_b64u, &jws->dat_b64u_len, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig(cjose_jws_t *jws, cjose_err *err)
{
    jws->dig_len = jws->hdr_b64u_len + jws->dat_b64u_len + 1;
    jws->dig = cjose_get_alloc()(jws->dig_len + 1);
    if (jws->dig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-5.1: B64U(HEADER).B64U(DATA)
    memcpy(jws->dig, jws->hdr_b64u, jws->hdr_b64u_len);
    jws->dig[jws->hdr_b64u_len] = '.';
    memcpy(jws->dig + jws->hdr_b64u_len + 1, jws->dat_b64u, jws->dat_b64u_len);

    return true;
}

static const EVP_MD *_cjose_jws_alg_to_md(cjose_jws_t *jws)
{
    json_t *obj = NULL;
    const char *alg = NULL;

    obj = json_object_get(jws->hdr, CJOSE_HDR_ALG);
    if (obj == NULL)
        return NULL;

    alg = json_string_value(obj);

    if ((strcmp(alg, CJOSE_HDR_ALG_RS256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS256) == 0)
        || (strcmp(alg, CJOSE_HDR_ALG_ES256) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS256) == 0))
        return EVP_sha256();

    else if ((strcmp(alg, CJOSE_HDR_ALG_RS384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS384) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES384) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS384) == 0))
        return EVP_sha384();

    else if ((strcmp(alg, CJOSE_HDR_ALG_RS512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_PS512) == 0)
             || (strcmp(alg, CJOSE_HDR_ALG_ES512) == 0) || (strcmp(alg, CJOSE_HDR_ALG_HS512) == 0))
        return EVP_sha512();

    return NULL;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_init(cjose_jws_t *jws, EVP_PKEY *pkey, EVP_PKEY_CTX **ppctx, cjose_err *err)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *alg = NULL;

    if ((pkey == NULL) || (ppctx == NULL) || (*ppctx != NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_init_fail;
    }

    alg = _cjose_jws_alg_to_md(jws);
    if (alg == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_init_fail;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_init_fail;
    }

    if (EVP_PKEY_sign_init_ex(pctx, NULL) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_init_fail;
    }

    if (EVP_PKEY_CTX_set_signature_md(pctx, alg) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_init_fail;
    }

    // check that we are dealing with a private key and not
    // a public one, and it needs to return CJOSE_ERR_INVALID_ARG
    // to satisfy the API tested in check_jws.c
    if (EVP_PKEY_private_check(pctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_sig_init_fail;
    }

    *ppctx = pctx;

    return true;

_cjose_jws_build_sig_init_fail:

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_digest_sig_init(cjose_jws_t *jws, EVP_PKEY *pkey, const EVP_MD *md, EVP_MD_CTX **pmctx, cjose_err *err)
{
    EVP_MD_CTX *mctx = NULL;

    if ((pkey == NULL) || (pmctx == NULL) || (*pmctx != NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_digest_sig_init_fail;
    }

    if (EVP_DigestSignInit(mctx, NULL, md, NULL, pkey) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_digest_sig_init_fail;
    }

    *pmctx = mctx;

    return true;

_cjose_jws_digest_sig_init_fail:

    if (mctx != NULL)
        EVP_MD_CTX_free(mctx);

    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_final(cjose_jws_t *jws, EVP_PKEY_CTX *pctx, cjose_err *err)
{
    // find out the length of the produced signature first to allocate a buffer for it
    if (EVP_PKEY_sign(pctx, NULL, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    jws->sig = cjose_get_alloc()(jws->sig_len);
    if (jws->sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    if (EVP_PKEY_sign(pctx, jws->sig, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_digest_sig_final(cjose_jws_t *jws, EVP_MD_CTX *mctx, cjose_err *err)
{
    // find out the length of the produced digested signature first to allocate a buffer for it
    if (EVP_DigestSign(mctx, NULL, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    jws->sig = cjose_get_alloc()(jws->sig_len);
    if (jws->sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    if (EVP_DigestSign(mctx, jws->sig, &jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_init(cjose_jws_t *jws, EVP_PKEY *pkey, EVP_PKEY_CTX **ppctx, cjose_err *err)
{
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *alg = NULL;

    if ((pkey == NULL) || (ppctx == NULL) || (*ppctx != NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    alg = _cjose_jws_alg_to_md(jws);
    if (alg == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_init_fail;
    }

    if (EVP_PKEY_verify_init(pctx) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_init_fail;
    }

    if (EVP_PKEY_CTX_set_signature_md(pctx, alg) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_init_fail;
    }

    if ((EVP_PKEY_public_check(pctx) != 1))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_verify_sig_init_fail;
    }

    *ppctx = pctx;

    return true;

_cjose_jws_verify_sig_init_fail:

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_digest_init(cjose_jws_t *jws, EVP_PKEY *pkey, const EVP_MD *md, EVP_MD_CTX **pmctx, cjose_err *err)
{
    EVP_MD_CTX *mctx = NULL;

    if ((pkey == NULL) || (pmctx == NULL) || (*pmctx != NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_digest_init_fail;
    }

    if (EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_digest_init_fail;
    }

    *pmctx = mctx;

    return true;

_cjose_jws_verify_digest_init_fail:

    if (mctx != NULL)
        EVP_MD_CTX_free(mctx);

    return false;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_final(cjose_jws_t *jws, EVP_PKEY_CTX *pctx, cjose_err *err)
{
    if (EVP_PKEY_verify(pctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_digest_final(cjose_jws_t *jws, EVP_MD_CTX *mctx, cjose_err *err)
{
    // NB: need to do one-shot verify here for EdDSA, cannot use EVP_DigestUpdate/EVP_DigestFinal
    if (EVP_DigestVerify(mctx, jws->sig, jws->sig_len, jws->dig, jws->dig_len) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool _cjose_jws_build_dig_rs(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (jwk->kty != CJOSE_JWK_KTY_RSA)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }
    return _cjose_jws_build_dig_sha(jws, jwk, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *alg = NULL;

    alg = _cjose_jws_alg_to_md(jws);
    if (alg == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    if (jws->dig != NULL)
    {
        cjose_get_dealloc()(jws->dig);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (jws->dig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // instantiate and initialize a new mac digest context
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_dig_sha_cleanup;
    }

    // create digest as DIGEST(B64U(HEADER).B64U(DATA))
    if (EVP_DigestInit_ex(ctx, alg, NULL) != 1)
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

    retval = true;

_cjose_jws_build_dig_sha_cleanup:

    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_hmac_sha(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;
    const EVP_MD *alg = NULL;

    // ensure jwk is OCT
    if (jwk->kty != CJOSE_JWK_KTY_OCT)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    alg = _cjose_jws_alg_to_md(jws);
    if (alg == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    if (jws->dig != NULL)
    {
        cjose_get_dealloc()(jws->dig);
        jws->dig = NULL;
    }

    // allocate buffer for digest
    jws->dig_len = EVP_MD_size(alg);
    jws->dig = (uint8_t *)cjose_get_alloc()(jws->dig_len);
    if (jws->dig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);
    if (mac == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_dig_hmac_sha_cleanup;
    }

    OSSL_PARAM params[2], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, (char *)EVP_MD_get0_name(alg), 0);
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

    retval = true;

_cjose_jws_build_dig_hmac_sha_cleanup:

    if (ctx != NULL)
        EVP_MAC_CTX_free(ctx);

    if (mac != NULL)
        EVP_MAC_free(mac);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_rsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, int padding, cjose_err *err)
{
    bool retval = false;
    EVP_PKEY_CTX *pctx = NULL;

    if (_cjose_jws_build_sig_init(jws, (EVP_PKEY *)jwk->keydata, &pctx, err) == false)
    {
        // error has already been set
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    if (_cjose_jws_build_sig_final(jws, pctx, err) == false)
    {
        // error has already been set
        goto _cjose_jws_build_sig_rsa_cleanup;
    }

    retval = cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err);

_cjose_jws_build_sig_rsa_cleanup:

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return retval;
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
    // allocate buffer for signature
    jws->sig_len = jws->dig_len;
    jws->sig = (uint8_t *)cjose_get_alloc()(jws->sig_len);
    if (jws->sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return false;
    }

    memcpy(jws->sig, jws->dig, jws->sig_len);

    // base64url encode signed digest
    return cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err);
}

bool _cjose_jws_build_dig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    if (jwk->kty != CJOSE_JWK_KTY_EC)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    return _cjose_jws_build_dig_sha(jws, jwk, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    ECDSA_SIG *ecdsa_sig = NULL;

    if (_cjose_jws_build_sig_init(jws, keydata->key, &pctx, err) == false)
    {
        // error has already been set
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    if (_cjose_jws_build_sig_final(jws, pctx, err) == false)
    {
        // error has already been set
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    // allocate buffer for signature
    switch (keydata->crv)
    {
    case CJOSE_JWK_EC_P_256:
        sig_len = 32 * 2;
        break;
    case CJOSE_JWK_EC_P_384:
        sig_len = 48 * 2;
        break;
    case CJOSE_JWK_EC_P_521:
        sig_len = 66 * 2;
        break;
    case CJOSE_JWK_EC_INVALID:
        sig_len = 0;
        break;
    }

    sig = (uint8_t *)cjose_get_alloc()(sig_len);
    if (sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto _cjose_jws_build_sig_ec_cleanup;
    }
    memset(sig, 0, sig_len);

    const unsigned char *p = jws->sig;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, jws->sig_len);
    if (ecdsa_sig == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_build_sig_ec_cleanup;
    }

    const BIGNUM *pr, *ps;
    ECDSA_SIG_get0(ecdsa_sig, &pr, &ps);
    int rlen = BN_num_bytes(pr);
    int slen = BN_num_bytes(ps);
    BN_bn2bin(pr, sig + sig_len / 2 - rlen);
    BN_bn2bin(ps, sig + sig_len - slen);

    cjose_get_dealloc()(jws->sig);
    jws->sig = sig;
    jws->sig_len = sig_len;

    // base64url encode signed digest
    retval = cjose_base64url_encode((const uint8_t *)jws->sig, jws->sig_len, &jws->sig_b64u, &jws->sig_b64u_len, err);

_cjose_jws_build_sig_ec_cleanup:

    if (ecdsa_sig != NULL)
        ECDSA_SIG_free(ecdsa_sig);

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_cser(cjose_jws_t *jws, cjose_err *err)
{
    // both sign and import should be setting these - but check just in case
    if ((jws->hdr_b64u == NULL) || (jws->dat_b64u == NULL) || (jws->sig_b64u == NULL))
    {
        return false;
    }

    // compute length of compact serialization
    jws->cser_len = jws->hdr_b64u_len + jws->dat_b64u_len + jws->sig_b64u_len + 3;

    if (jws->cser != NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_STATE);
        return false;
    }

    // allocate buffer for compact serialization
    jws->cser = (char *)cjose_get_alloc()(jws->cser_len);
    if (jws->cser == NULL)
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

    if ((jwk == NULL) || (protected_header == NULL) || (plaintext == NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return NULL;
    }

    // allocate and initialize JWS
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (jws == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        return NULL;
    }
    memset(jws, 0, sizeof(cjose_jws_t));

    // build JWS header
    if (_cjose_jws_build_hdr(jws, protected_header, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // validate JWS header
    if (_cjose_jws_validate_hdr(jws, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build the JWS data segment
    if (_cjose_jws_build_dat(jws, plaintext, plaintext_len, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS digest (hashed signing input value)
    if (jws->fns.digest(jws, jwk, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // sign the JWS digest
    if (jws->fns.sign(jws, jwk, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    // build JWS compact serialization
    if (_cjose_jws_build_cser(jws, err) == false)
    {
        cjose_jws_release(jws);
        return NULL;
    }

    return jws;
}

////////////////////////////////////////////////////////////////////////////////
void cjose_jws_release(cjose_jws_t *jws)
{
    if (jws == NULL)
        return;

    if (jws->hdr != NULL)
        json_decref(jws->hdr);

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
    if ((jws == NULL) || (compact == NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    if (jws->cser == NULL)
        _cjose_jws_build_cser(jws, err);

    *compact = jws->cser;
    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_strcpy(char **dst, const char *src, int len, cjose_err *err)
{
    if (dst == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    *dst = (char *)cjose_get_alloc()(len + 1);
    if (*dst == NULL)
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

    if (cser == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // allocate and initialize a new JWS object
    jws = (cjose_jws_t *)cjose_get_alloc()(sizeof(cjose_jws_t));
    if (jws == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_NO_MEMORY);
        goto cjose_jws_import_fail;
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
    if (d[1] == 0)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // copy and decode header b64u segment
    uint8_t *hdr_str = NULL;
    jws->hdr_b64u_len = d[0];
    _cjose_jws_strcpy(&jws->hdr_b64u, cser, jws->hdr_b64u_len, err);
    if ((cjose_base64url_decode(jws->hdr_b64u, jws->hdr_b64u_len, &hdr_str, &len, err) == false) || (hdr_str == NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // deserialize JSON header
    jws->hdr = json_loadb((const char *)hdr_str, len, 0, NULL);
    cjose_get_dealloc()(hdr_str);
    if (jws->hdr == NULL)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // validate the JSON header segment
    if (_cjose_jws_validate_hdr(jws, err) == false)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // copy and b64u decode data segment
    jws->dat_b64u_len = d[1] - d[0] - 1;
    _cjose_jws_strcpy(&jws->dat_b64u, cser + d[0] + 1, jws->dat_b64u_len, err);
    if (cjose_base64url_decode(jws->dat_b64u, jws->dat_b64u_len, &jws->dat, &jws->dat_len, err) == false)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    // copy and b64u decode signature segment
    jws->sig_b64u_len = cser_len - d[1] - 1;
    _cjose_jws_strcpy(&jws->sig_b64u, cser + d[1] + 1, jws->sig_b64u_len, err);
    if (cjose_base64url_decode(jws->sig_b64u, jws->sig_b64u_len, &jws->sig, &jws->sig_len, err) == false)
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        goto cjose_jws_import_fail;
    }

    return jws;

cjose_jws_import_fail:

    if (jws != NULL)
        cjose_jws_release(jws);

    return NULL;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_rsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, int padding, cjose_err *err)
{
    bool retval = false;
    EVP_PKEY_CTX *pctx = NULL;

    if (_cjose_jws_verify_sig_init(jws, jwk->keydata, &pctx, err) == false)
    {
        // error has already been set
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) != 1)
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        goto _cjose_jws_verify_sig_rsa_cleanup;
    }

    retval = _cjose_jws_verify_sig_final(jws, pctx, err);

_cjose_jws_verify_sig_rsa_cleanup:

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

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
    // verify decrypted digest matches computed digest
    if ((cjose_const_memcmp(jws->dig, jws->sig, jws->dig_len) != 0) || (jws->sig_len != jws->dig_len))
    {
        CJOSE_ERROR(err, CJOSE_ERR_CRYPTO);
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_ec(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    ec_keydata *keydata = (ec_keydata *)jwk->keydata;
    EVP_PKEY_CTX *pctx = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    unsigned char *der_sig = NULL;

    if (_cjose_jws_verify_sig_init(jws, keydata->key, &pctx, err) == false)
    {
        // error has already been set
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

    cjose_get_dealloc()(jws->sig);
    jws->sig = der_sig;
    jws->sig_len = der_sig_len;

    retval = _cjose_jws_verify_sig_final(jws, pctx, err);

_cjose_jws_verify_sig_ec_cleanup:

    if (ecdsa_sig != NULL)
        ECDSA_SIG_free(ecdsa_sig);

    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_dig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    // avoid using keys that must not be used for signing i.e. X25519 and X448
    switch (cjose_jwk_OKP_get_curve(jwk, err))
    {
    case CJOSE_JWK_OKP_ED25519:
    case CJOSE_JWK_OKP_ED448:
        break;
    default:
        return false;
        break;
    }
    // PureEdDSA (ed25519) does not support streaming with EVP_DigestSignUpdate/EVP_DigestVerifyUpdate
    return _cjose_jws_build_dig(jws, err);
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_build_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    EVP_MD_CTX *mctx = NULL;

    if (_cjose_jws_digest_sig_init(jws, keydata->key, NULL, &mctx, err) == false)
    {
        // error has been set
        goto _cjose_jws_build_sig_eddsa_cleanup;
    }

    retval = _cjose_jws_digest_sig_final(jws, mctx, err);

_cjose_jws_build_sig_eddsa_cleanup:

    if (mctx != NULL)
        EVP_MD_CTX_free(mctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
static bool _cjose_jws_verify_sig_eddsa(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    bool retval = false;
    okp_keydata *keydata = (okp_keydata *)jwk->keydata;
    EVP_MD_CTX *mctx = NULL;

    if (_cjose_jws_verify_digest_init(jws, keydata->key, NULL, &mctx, err) == false)
    {
        // error has been set
        goto _cjose_jws_verify_sig_eddsa_cleanup;
    }

    retval = _cjose_jws_verify_digest_final(jws, mctx, err);

_cjose_jws_verify_sig_eddsa_cleanup:

    if (mctx != NULL)
        EVP_MD_CTX_free(mctx);

    return retval;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_verify(cjose_jws_t *jws, const cjose_jwk_t *jwk, cjose_err *err)
{
    if ((jws == NULL) || (jwk == NULL))
    {
        CJOSE_ERROR(err, CJOSE_ERR_INVALID_ARG);
        return false;
    }

    // validate JWS header
    if (_cjose_jws_validate_hdr(jws, err) == false)
        return false;

    // build JWS digest from header and payload (hashed signing input value)
    if (jws->fns.digest(jws, jwk, err) == false)
        return false;

    // verify JWS signature
    if (jws->fns.verify(jws, jwk, err) == false)
        return false;

    return true;
}

////////////////////////////////////////////////////////////////////////////////
bool cjose_jws_get_plaintext(const cjose_jws_t *jws, uint8_t **plaintext, size_t *plaintext_len, cjose_err *err)
{
    if ((jws == NULL) || (plaintext == NULL) || (jws->dat == NULL))
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
    if (jws == NULL)
        return NULL;

    return (cjose_header_t *)jws->hdr;
}
