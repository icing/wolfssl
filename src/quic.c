/* quic.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


  /* Name change compatibility layer no longer needs to be included here */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY
#ifdef WOLFSSL_QUIC

#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>


static int ctx_check_quic_compat(const WOLFSSL_CTX *ctx)
{
    if (ctx->method->version.major != SSLv3_MAJOR
        || ctx->method->version.minor != TLSv1_3_MINOR
        || ctx->method->downgrade) {
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
}


int wolfSSL_CTX_set_quic_method(WOLFSSL_CTX *ctx, const WOLFSSL_QUIC_METHOD *quic_method)
{
    if (ctx_check_quic_compat(ctx) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }
    ctx->quic.method = quic_method;
    /* TODO: TLSv1.3 middlebox compatibility should be disabled for QUIC,
     * but there seems to be no flag to do so if WOLFSSL_TLS13_MIDDLEBOX_COMPAT
     * is configured?
     */
    return WOLFSSL_SUCCESS;
}


int wolfSSL_set_quic_method(WOLFSSL *ssl, const WOLFSSL_QUIC_METHOD *quic_method)
{
    if (ctx_check_quic_compat(ssl->ctx) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }
    ssl->quic.method = quic_method;
    /* TODO: TLSv1.3 middlebox compatibility should be disabled for QUIC,
     * but there seems to be no flag to do so if WOLFSSL_TLS13_MIDDLEBOX_COMPAT
     * is configured?
     */
    return WOLFSSL_SUCCESS;
}


int wolfSSL_is_quic(WOLFSSL *ssl)
{
    return WOLFSSL_IS_QUIC(ssl);
}


WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_read_level(const WOLFSSL *ssl)
{
    return ssl->quic.enc_level_read;
}


WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_write_level(const WOLFSSL *ssl)
{
    return ssl->quic.enc_level_write;
}


int wolfSSL_set_quic_transport_params(WOLFSSL *ssl,
                                      const uint8_t *params,
                                      size_t params_len)
{
    uint8_t *nparams;
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("SSL_set_quic_transport_params");

    if (!params || params_len == 0) {
        nparams = NULL;
        params_len = 0;
    }
    else {
        nparams = (uint8_t*) XMALLOC(params_len, ssl->heap, DYNAMIC_TYPE_SSL);
        if (!nparams) {
            ret = WOLFSSL_FAILURE;
            goto cleanup;
        }
        XMEMCPY(nparams, params, params_len);
    }
    if (ssl->quic.transport_params.our)
        XFREE(ssl->quic.transport_params.our, ssl->heap, DYNAMIC_TYPE_SSL);
    ssl->quic.transport_params.our = nparams;
    ssl->quic.transport_params.our_len = params_len;

cleanup:
    WOLFSSL_LEAVE("SSL_set_quic_transport_params", ret);
    return ret;
}


void SSL_get_peer_quic_transport_params(const WOLFSSL *ssl,
                                        const uint8_t **out_params,
                                        size_t *out_params_len)
{
    if (ssl->quic.transport_params.peer_len) {
        *out_params = ssl->quic.transport_params.peer;
        *out_params_len = ssl->quic.transport_params.peer_len;
    } else {
        *out_params = ssl->quic.transport_params.peer_draft;
        *out_params_len = ssl->quic.transport_params.peer_draft_len;
    }
}


#define QUIC_HS_FLIGHT_LIMIT_DEFAULT      (16 * 1024)

size_t wolfSSL_quic_max_handshake_flight_len(const WOLFSSL *ssl,
                                             WOLFSSL_ENCRYPTION_LEVEL level)
{
    switch (level) {
        case wolfssl_encryption_initial:
        case wolfssl_encryption_application:
                return QUIC_HS_FLIGHT_LIMIT_DEFAULT;
        case wolfssl_encryption_early_data:
            return 0; /* QUIC does not send at this level */
        case wolfssl_encryption_handshake:
            /* during handshake itself, certificates may be exchanged which
             * exceed our default limit, advise a higher limit to avoid blocking.
             */
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if (ssl->options.verifyPeer
                    && MAX_CERTIFICATE_SZ > QUIC_HS_FLIGHT_LIMIT_DEFAULT)
                    return MAX_CERTIFICATE_SZ;
            }
            else {
                /* clients may receive the server cert chain and certificate requests
                 */
                if (2*MAX_CERTIFICATE_SZ > QUIC_HS_FLIGHT_LIMIT_DEFAULT)
                    return 2*MAX_CERTIFICATE_SZ;
            }
            return QUIC_HS_FLIGHT_LIMIT_DEFAULT;
    }
    return 0;
}


void wolfSSL_set_quic_use_legacy_codepoint(WOLFSSL *ssl, int use_legacy)
{
    ssl->quic.transport_version = use_legacy? WOLFSSL_TLSEXT_QUIC_TP_PARAMS_DRAFT
        : WOLFSSL_TLSEXT_QUIC_TP_PARAMS;
}

void wolfSSL_set_quic_transport_version(WOLFSSL *ssl, int version)
{
    ssl->quic.transport_version = version;
}


int wolfSSL_get_quic_transport_version(const WOLFSSL *ssl)
{
    return ssl->quic.transport_version;
}


int wolfSSL_CIPHER_get_prf_nid(const WOLFSSL_CIPHER *c)
{
    /* TODO: extract the NID of the pseudo random function (PRF)
     * used with the cipher. This is an addition in the quictls-openssl
     * patch, but ngtcp2 does *not* use it. Instead it retrieves the
     * current cipher from the SSL* and figures the MD by looking at the
     * cipher id.
     */
     (void)c;
     return 0;
}


#endif /* WOLFSSL_QUIC */
#endif /* WOLFCRYPT_ONLY */

