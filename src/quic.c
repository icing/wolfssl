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
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLFCRYPT_ONLY
#ifdef WOLFSSL_QUIC

#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#include <wolfssl/openssl/buffer.h>

static int qr_length(const uint8_t *data, size_t len)
{
    word32 rlen;
    if (len < 4) {
        return 0;
    }
    c24to32(&data[1], &rlen);
    return (int)rlen + 4;
}

static void quic_record_free(WOLFSSL *ssl, QuicRecord *r)
{
    (void)ssl;
    if (r->data) {
        ForceZero(r->data, r->capacity);
        XFREE(r->data, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(r, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
}


static QuicRecord *quic_record_make(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                    const uint8_t *data, size_t len)
{
    QuicRecord *qr;

    qr = XMALLOC(sizeof(*qr), ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (qr) {
        memset(qr, 0, sizeof(*qr));
        qr->level = level;
        qr->capacity = qr->len = qr_length(data, len);
        if (qr->capacity == 0) {
            qr->capacity = 2*1024;
        }
        qr->data = XMALLOC(qr->capacity, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (!qr->data) {
            quic_record_free(ssl, qr);
            return NULL;
        }
    }
    return qr;
}

static int quic_record_complete(QuicRecord *r)
{
    return r->len && r->end >= r->len;
}

static int quic_record_done(QuicRecord *r)
{
    return r->len && r->end >= r->len && r->start >= r->end;
}

static int quic_record_append(WOLFSSL *ssl, QuicRecord *qr, const uint8_t *data,
                              size_t len, size_t *pconsumed)
{
    size_t missing, consumed = 0;
    int ret = WOLFSSL_SUCCESS;

    (void)ssl;
    if (!qr->len && len) {
        missing = 4 - qr->end;
        if (len < missing) {
            XMEMCPY(qr->data + qr->end, data, len);
            qr->end += len;
            consumed = len;
            goto cleanup; /* len consumed, but qr->len still unkown */
        }
        XMEMCPY(qr->data + qr->end, data, missing);
        qr->end += missing;
        len -= missing;
        data += missing;
        consumed = missing;

        qr->len = qr_length(qr->data, qr->end);
        if (qr->len > qr->capacity) {
            uint8_t *ndata = XREALLOC(qr->data, qr->len, ssl->head, DYNAMIC_TYPE_TMP_BUFFER);
            if (!ndata) {
                ret = WOLFSSL_FAILURE;
                goto cleanup;
            }
            qr->data = ndata;
            qr->capacity = qr->len;
        }
    }

    if (quic_record_complete(qr) || len == 0) {
        return 0;
    }

    missing = qr->len - qr->end;
    if (len > missing) {
        len = missing;
    }
    XMEMCPY(qr->data + qr->end, data, len);
    qr->end += len;
    consumed += len;

cleanup:
    *pconsumed = (ret == WOLFSSL_SUCCESS)? consumed : 0;
    return ret;
}


static word32 quic_record_transfer(QuicRecord *qr, byte *buf, word32 sz)
{
    word32 len = min(qr->end - qr->start, sz);

    if (len <= 0) {
        return 0;
    }
    XMEMCPY(buf, qr->data + qr->start, len);
    qr->start += len;
    return len;
}


void QuicFreeResources(WOLFSSL* ssl)
{
    QuicEncData *qd;

    if (ssl->quic.transport_params.our) {
        XFREE(ssl->quic.transport_params.our, ssl->heap, DYNAMIC_TYPE_SSL);
        ssl->quic.transport_params.our = NULL;
    }
    if (ssl->quic.transport_params.peer) {
        XFREE(ssl->quic.transport_params.peer, ssl->heap, DYNAMIC_TYPE_SSL);
        ssl->quic.transport_params.peer = NULL;
    }
    if (ssl->quic.transport_params.peer_draft) {
        XFREE(ssl->quic.transport_params.peer_draft, ssl->heap, DYNAMIC_TYPE_SSL);
        ssl->quic.transport_params.peer_draft = NULL;
    }

    while ((qd = ssl->quic.input_head)) {
        ssl->quic.input_head = qd->next;
        quic_record_free(ssl, qd);
    }
    ssl->quic.input_tail = NULL;

    if (ssl->quic.scratch) {
        quic_record_free(ssl, ssl->quic.scratch);
        ssl->quic.scratch = NULL;
    }
    ssl->quic.method = NULL;
}


static int ctx_check_quic_compat(const WOLFSSL_CTX *ctx)
{
    if (ctx->method->version.major != SSLv3_MAJOR
        || ctx->method->version.minor != TLSv1_3_MINOR
        || ctx->method->downgrade) {
        return WOLFSSL_FAILURE;
    }
    return WOLFSSL_SUCCESS;
}

static int check_method_sanity(const WOLFSSL_QUIC_METHOD *m)
{
    if (m && m->set_encryption_secrets
        && m->add_handshake_data
        && m->flush_flight
        && m->send_alert) {
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

int wolfSSL_CTX_set_quic_method(WOLFSSL_CTX *ctx, const WOLFSSL_QUIC_METHOD *quic_method)
{
    if (ctx_check_quic_compat(ctx) != WOLFSSL_SUCCESS
        || check_method_sanity(quic_method) != WOLFSSL_SUCCESS) {
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
    if (ctx_check_quic_compat(ssl->ctx) != WOLFSSL_SUCCESS
        || check_method_sanity(quic_method) != WOLFSSL_SUCCESS) {
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

    if (!wolfSSL_is_quic(ssl)) {
        ret = WOLFSSL_FAILURE;
        goto cleanup;
    }

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


void wolfSSL_get_peer_quic_transport_params(const WOLFSSL *ssl,
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


#ifdef WOLFSSL_EARLY_DATA
void wolfSSL_set_quic_early_data_enabled(WOLFSSL *ssl, int enabled)
{
    /* This only has effect on server and when the handshake has
     * not started yet. For clients, we have no internal options
     * state that would make wolfSSL_write_early_data() fail inspite
     * the server supporting it.
     * So we silently ignore all these cases. The use case for this
     * function seems to be designed for servers.
     */
    if (wolfSSL_is_quic(ssl)
        && ssl->options.handShakeState == NULL_STATE
        && ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->options.maxEarlyDataSz = enabled? MAX_EARLY_DATA_SZ : 0;
    }
}
#endif /* WOLFSSL_EARLY_DATA */


int wolfSSL_CIPHER_get_prf_nid(const WOLFSSL_CIPHER *c)
{
    /* TODO: extract the NID of the pseudo random function (PRF)
     * used with the cipher. This is an addition in the quictls-openssl
     * patch, but ngtcp2 does *not* use it. Instead it retrieves the
     * current cipher from the SSL* and figures the MD by looking at the
     * cipher id.
     */
     (void)c;
     return WOLFSSL_FAILURE;
}


int wolfSSL_process_quic_post_handshake(WOLFSSL *ssl)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_process_quic_post_handshake");

    if (!wolfSSL_is_quic(ssl)) {
        WOLFSSL_MSG("WOLFSSL_QUIC_POST_HS not a QUIC SSL");
        ret = WOLFSSL_FAILURE;
        goto cleanup;
    }

    if (ssl->options.handShakeState == NULL_STATE) {
        WOLFSSL_MSG("WOLFSSL_QUIC_POST_HS handshake not started");
        ret = WOLFSSL_FAILURE;
        goto cleanup;
    }

    while (ssl->quic.input_head != NULL) {
        /* TODO: process and consume the data for handshake */
    }

cleanup:
    WOLFSSL_LEAVE("wolfSSL_process_quic_post_handshake", ret);
    return ret;
}


int wolfSSL_provide_quic_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len)
{
    int ret = WOLFSSL_SUCCESS;
    size_t l;

    WOLFSSL_ENTER("wolfSSL_provide_quic_data");
    if (!wolfSSL_is_quic(ssl)) {
        WOLFSSL_MSG("WOLFSSL_QUIC_PROVIDE_DATA not a QUIC SSL");
        ret = WOLFSSL_FAILURE;
        goto cleanup;
    }

    if (level < ssl->quic.enc_level_read
        || (ssl->quic.input_tail && level < ssl->quic.input_tail->level)
        || level < ssl->quic.enc_level_latest_recvd) {
        WOLFSSL_MSG("WOLFSSL_QUIC_PROVIDE_DATA wrong encryption level");
        ret = WOLFSSL_FAILURE;
        goto cleanup;
    }

    while (len > 0) {
        if (ssl->quic.scratch) {
            if (ssl->quic.scratch->level != level) {
                WOLFSSL_MSG("WOLFSSL_QUIC_PROVIDE_DATA wrong encryption level");
                ret = WOLFSSL_FAILURE;
                goto cleanup;
            }

            ret = quic_record_append(ssl, ssl->quic.scratch, data, len, &l);
            if (ret != WOLFSSL_SUCCESS) {
                goto cleanup;
            }
            data += l;
            len -= l;
            if (quic_record_complete(ssl->quic.scratch)) {
                if (ssl->quic.input_tail) {
                    ssl->quic.input_tail->next = ssl->quic.scratch;
                    ssl->quic.input_tail = ssl->quic.scratch;
                }
                else {
                    ssl->quic.input_head = ssl->quic.input_tail = ssl->quic.scratch;
                }
                ssl->quic.scratch = NULL;
            }
        }
        else {
            /* start of next record with all bytes for the header */
            ssl->quic.scratch = quic_record_make(ssl, level, data, len);
            if (!ssl->quic.scratch) {
                ret = WOLFSSL_FAILURE;
                goto cleanup;
            }
        }
    }

cleanup:
    WOLFSSL_LEAVE("wolfSSL_provide_quic_data", ret);
    return ret;
}


/* Called internally when SSL wants a certain amount of input. */
int wolfSSL_quic_receive(WOLFSSL* ssl, byte* buf, word32 sz)
{
    word32 n, transferred = 0;

    WOLFSSL_ENTER("wolfSSL_quic_receive");
    while (sz > 0) {
        n = 0;
        if (ssl->quic.input_head) {
            n = quic_record_transfer(ssl->quic.input_head, buf, sz);
            if (quic_record_done(ssl->quic.input_head)) {
                QuicRecord *qr = ssl->quic.input_head;
                ssl->quic.input_head = qr->next;
                if (!qr->next) {
                    ssl->quic.input_tail = NULL;
                }
                quic_record_free(ssl, qr);
            }
        }

        if (n == 0) {
            if (transferred > 0) {
                goto cleanup;
            }
            return WANT_READ;
        }
        sz -= n;
        buf += n;
        transferred += n;
    }
cleanup:
    WOLFSSL_LEAVE("wolfSSL_quic_receive", transferred);
    return transferred;
}


int wolfSSL_quic_send(WOLFSSL* ssl)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_quic_send");
    if (ssl->buffers.outputBuffer.length > 0) {
        /* TODO: Are we in handshake? */
        ret = ssl->quic.method->add_handshake_data(
            ssl, ssl->quic.enc_level_write,
            (const uint8_t*)ssl->buffers.outputBuffer.buffer +
                ssl->buffers.outputBuffer.idx,
            ssl->buffers.outputBuffer.length);
        if (!ret) {
            /* The application has an error. General desaster. */
            WOLFSSL_MSG("WOLFSSL_QUIC_SEND application returned error");
            ret = -1;
            goto cleanup;
        }
    }
cleanup:
    WOLFSSL_LEAVE("wolfSSL_quic_send", ret);
    return ret;
}


#endif /* WOLFSSL_QUIC */
#endif /* WOLFCRYPT_ONLY */

