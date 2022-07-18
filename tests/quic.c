/* quic.c QUIC unit tests
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <tests/unit.h>

#ifdef WOLFSSL_QUIC

#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>


#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed = "passed";
static const char* failed = "failed";

typedef struct {
    const char *name;
    WOLFSSL_METHOD *method;
    int is_server;
} ctx_setups;

static int dummy_set_encryption_secrets(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                         const uint8_t *read_secret,
                                         const uint8_t *write_secret, size_t secret_len)
{
    (void)ssl;
    printf("QUIC_set_encryption_secrets(level=%d, length=%lu, rx=%s, tx=%s)\n",
           level, secret_len, read_secret? "yes" : "no", write_secret? "yes" : "no");
    return 1;
}

static int dummy_add_handshake_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                    const uint8_t *data, size_t len)
{
    (void)ssl;
    (void)data;
    printf("QUIC_add_handshake_data(level=%d, length=%lu)\n", level, len);
    return 1;
}

static int dummy_flush_flight(WOLFSSL *ssl)
{
    (void)ssl;
    printf("QUIC_flush_flight()\n");
    return 1;
}

static int dummy_send_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert)
{
    (void)ssl;
    printf("QUIC_send_alert(level=%d, alert=%d)\n", level, alert);
    return 1;
}

static WOLFSSL_QUIC_METHOD dummy_method = {
    dummy_set_encryption_secrets,
    dummy_add_handshake_data,
    dummy_flush_flight,
    dummy_send_alert,
};

static WOLFSSL_QUIC_METHOD null_method = {
    NULL, NULL, NULL, NULL
};

static int test_set_quic_method(void) {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int ret = 0, i;
    const uint8_t *data;
    size_t data_len;
    ctx_setups valids[] = {
        { "TLSv1.3 server", wolfTLSv1_3_server_method(), 1},
        { "TLSv1.3 client", wolfTLSv1_3_client_method(), 0},
    };
    ctx_setups invalids[] = {
        { "TLSv1.2 server", wolfTLSv1_2_server_method(), 1},
        { "TLSv1.2 client", wolfTLSv1_2_client_method(), 0},
        { "TLSv1.1 server", wolfTLSv1_1_server_method(), 1},
        { "TLSv1.1 client", wolfTLSv1_1_client_method(), 0},
    };

    for (i = 0; i < (int)(sizeof(valids)/sizeof(valids[0])); ++i) {
        printf("   wolfSSL_set_quic_method(%s)", valids[i].name);

        AssertNotNull(ctx = wolfSSL_CTX_new(valids[i].method));
        if (valids[i].is_server) {
            AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
                                                        WOLFSSL_FILETYPE_PEM));
            AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
                                                       WOLFSSL_FILETYPE_PEM));
        }
        /* ctx does not have quic enabled, so will SSL* derived from it */
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertFalse(wolfSSL_is_quic(ssl));
        /* Enable quic on the SSL* */
        AssertFalse(wolfSSL_set_quic_method(ssl, &null_method) == WOLFSSL_SUCCESS);
        AssertTrue(wolfSSL_set_quic_method(ssl, &dummy_method) == WOLFSSL_SUCCESS);
        AssertTrue(wolfSSL_is_quic(ssl));
        /* Check some default, initial behaviour */
        AssertTrue(wolfSSL_set_quic_transport_params(ssl, NULL, 0) == WOLFSSL_SUCCESS);
        wolfSSL_get_peer_quic_transport_params(ssl, &data, &data_len);
        AssertNull(data);
        AssertTrue(data_len == 0);
        AssertTrue(wolfSSL_quic_read_level(ssl) == wolfssl_encryption_initial);
        AssertTrue(wolfSSL_quic_write_level(ssl) == wolfssl_encryption_initial);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == 0);
        wolfSSL_set_quic_transport_version(ssl, TLSX_KEY_QUIC_TP_PARAMS);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == TLSX_KEY_QUIC_TP_PARAMS);
        wolfSSL_set_quic_use_legacy_codepoint(ssl, 1);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == TLSX_KEY_QUIC_TP_PARAMS_DRAFT);
        wolfSSL_set_quic_use_legacy_codepoint(ssl, 0);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == TLSX_KEY_QUIC_TP_PARAMS);
        /* max flight len during stages of handhshake, we us 16k initial and on
         * app data, and during handshake allow larger for cert exchange. This is
         * more advisory for the network code. ngtcp2 has its own ideas, for example.
         */
        data_len = wolfSSL_quic_max_handshake_flight_len(ssl, wolfssl_encryption_initial);
        AssertTrue(data_len == 16*1024);
        data_len = wolfSSL_quic_max_handshake_flight_len(ssl, wolfssl_encryption_early_data);
        AssertTrue(data_len == 0);
        data_len = wolfSSL_quic_max_handshake_flight_len(ssl, wolfssl_encryption_handshake);
        AssertTrue(data_len >= 16*1024);
        data_len = wolfSSL_quic_max_handshake_flight_len(ssl, wolfssl_encryption_application);
        AssertTrue(data_len == 16*1024);
        wolfSSL_free(ssl);
        /* Enabled quic on the ctx */
        AssertTrue(wolfSSL_CTX_set_quic_method(ctx, &dummy_method) == WOLFSSL_SUCCESS);
        /* It will be enabled on the SSL* */
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertTrue(wolfSSL_is_quic(ssl));
        wolfSSL_free(ssl);

        wolfSSL_CTX_free(ctx);
        printf(": %s\n", (ret == 0)? passed : failed);
    }

    for (i = 0; i < (int)(sizeof(invalids)/sizeof(invalids[0])); ++i) {
        printf("   wolfSSL_set_quic_method(%s)", invalids[i].name);

        AssertNotNull(ctx = wolfSSL_CTX_new(invalids[i].method));
        AssertTrue(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
                                                    WOLFSSL_FILETYPE_PEM));
        AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile,
                                                   WOLFSSL_FILETYPE_PEM));
        AssertFalse(wolfSSL_CTX_set_quic_method(ctx, &dummy_method) == WOLFSSL_SUCCESS);
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertFalse(wolfSSL_set_quic_method(ssl, &dummy_method) == WOLFSSL_SUCCESS);
        AssertFalse(wolfSSL_is_quic(ssl));
        /* even though not quic, this is the only level we can return */
        AssertTrue(wolfSSL_quic_read_level(ssl) == wolfssl_encryption_initial);
        AssertTrue(wolfSSL_quic_write_level(ssl) == wolfssl_encryption_initial);
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        printf(": %s\n", (ret == 0)? passed : failed);
    }

    return ret;
}

static size_t fake_record(byte rtype, word32 rlen, uint8_t *buffer)
{
    buffer[0] = (uint8_t)rtype;
    c32to24(rlen, buffer+1);
    return rlen + 4;
}

static size_t shift_record(uint8_t *buffer, size_t len, size_t written)
{
    len -= written;
    XMEMMOVE(buffer, buffer+written, len);
    return len;
}

static void dump_buffer(const char *name, const byte *p, size_t len, int indent)
{
    size_t i = 0;

    printf("%s[%lu] = {", name, len);
    while((p != NULL) && (i < len)) {
        if((i % 0x10) == 0) {
            printf("\n");
            printf("%*s  %04X - ", indent, " ", (int)(i / 0x10));
        }
        else if((i % 0x08) == 0) {
            printf("  ");
        }
        printf("%02X ", p[i]);
        i++;
    }
    printf("\n%*s};\n", indent, " ");
}

static void dump_ssl_buffers(WOLFSSL *ssl, FILE *fp)
{
    QuicRecord *qr = ssl->quic.input_head;

    fprintf(fp, "SSL quic data buffered: \n");
    while (qr) {
        fprintf(fp, "  - %d-%d/%d (cap %d, level=%d)\n",
                qr->start, qr->end, qr->len, qr->capacity, qr->level);
        qr = qr->next;
    }
    if ((qr = ssl->quic.scratch)) {
        fprintf(fp, "  scratch: %d-%d/%d (cap %d, level=%d)\n",
                qr->start, qr->end, qr->len, qr->capacity, qr->level);
    }
    else {
        fprintf(fp, "  scratch: -\n");
    }
}

static int provide_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                        const uint8_t *data, size_t len, int excpect_fail)
{
    int ret;

    ret = (wolfSSL_provide_quic_data(ssl, level, data, len) == WOLFSSL_SUCCESS);
    if (!!ret != !excpect_fail) {
        dump_ssl_buffers(ssl, stdout);
        return 0;
    }
    return 1;
}

static int test_provide_quic_data(void) {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    uint8_t buffer[16*1024];
    size_t len;
    int ret = 0;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    AssertTrue(wolfSSL_CTX_set_quic_method(ctx, &dummy_method) == WOLFSSL_SUCCESS);
    /* provide_quic_data() feeds CRYPTO packets inside a QUIC Frame into
    * the TLSv1.3 state machine.
     * The data fed is not the QUIC frame, but the TLS record inside it.
     * This may be called several times before SSL_do_handshake() is invoked
     * to process them.
     * During buffering this data, the code checks that:
     * - encryption level only ever increases for subsequent TLS records
     * - a TLS record is received complete before the encryption level increases
     */
    printf("   wolfSSL_provide_quic_data(complete recs)");
    AssertNotNull(ssl = wolfSSL_new(ctx));
    len = fake_record(1, 100, buffer);
    AssertTrue(provide_data(ssl, wolfssl_encryption_initial, buffer, len, 0));
    len = fake_record(2, 1523, buffer);
    AssertTrue(provide_data(ssl, wolfssl_encryption_handshake, buffer, len, 0));
    len = fake_record(2, 1, buffer);
    len += fake_record(3, 190, buffer+len);
    AssertTrue(provide_data(ssl, wolfssl_encryption_handshake, buffer, len, 0));
    len = fake_record(5, 2049, buffer);
    AssertTrue(provide_data(ssl, wolfssl_encryption_application, buffer, len, 0));
    /* adding another record with decreased level must fail */
    len = fake_record(1, 100, buffer);
    AssertTrue(provide_data(ssl, wolfssl_encryption_initial, buffer, len, 1));
    printf(": %s\n", (ret == 0)? passed : failed);
    wolfSSL_free(ssl);

    printf("   wolfSSL_provide_quic_data(incomplete recs)");
    AssertNotNull(ssl = wolfSSL_new(ctx));
    len = fake_record(1, 100, buffer);
    AssertTrue(provide_data(ssl, wolfssl_encryption_initial, buffer, 24, 0));
    len = shift_record(buffer, len, 24);
    len += fake_record(2, 4000, buffer+len);
    AssertTrue(provide_data(ssl, wolfssl_encryption_initial, buffer, len - 99, 0));
    len = shift_record(buffer, len, len - 99);
    len += fake_record(5, 2049, buffer+len);
    AssertTrue(provide_data(ssl, wolfssl_encryption_initial, buffer, len, 0));
    /* should be recognized as complete and level increase needs to be accepted */
    len = fake_record(2, 1, buffer);
    len += fake_record(3, 190, buffer+len);
    AssertTrue(provide_data(ssl, wolfssl_encryption_handshake, buffer, len - 10, 0));
    len = shift_record(buffer, len, len - 10);
    /* Change level with incomplete record in buffer, needs to fail */
    len += fake_record(5, 8102, buffer+len);
    AssertTrue(provide_data(ssl, wolfssl_encryption_application, buffer, len - 10, 1));
    printf(": %s\n", (ret == 0)? passed : failed);
    wolfSSL_free(ssl);


    wolfSSL_CTX_free(ctx);

    return 0;
}


static int test_quic_crypt(void) {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    const WOLFSSL_EVP_CIPHER *aead;
    int ret = 0;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    AssertTrue(wolfSSL_CTX_set_quic_method(ctx, &dummy_method) == WOLFSSL_SUCCESS);
    AssertNotNull(ssl = wolfSSL_new(ctx));

    /* don't have an AEAD cipher selected before start */
    AssertTrue(wolfSSL_CIPHER_get_id(wolfSSL_get_current_cipher(ssl)) == 0);
    AssertNotNull(aead = wolfSSL_EVP_aes_128_gcm());
    AssertTrue(wolfSSL_quic_aead_is_gcm(aead) != 0);
    AssertTrue(wolfSSL_quic_aead_is_ccm(aead) == 0);
    AssertTrue(wolfSSL_quic_aead_is_chacha20(aead) == 0);

    if (1) {
        /* check that our enc-/decrypt support in quic rount-trips */
        static const uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        static const uint8_t aad[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
        static const uint8_t iv[] = {20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
        static const uint8_t plaintext[] = "hello world\nhello world\nhello world\nhello world\nhello world\nhello world\nhello world\n";
        static const uint8_t expected[] = {0xd3, 0xa8, 0x1d, 0x96, 0x4c, 0x9b, 0x02, 0xd7, 0x9a, 0xb0, 0x41, 0x07, 0x4c, 0x8c, 0xe2,
                                           0xe0, 0x2e, 0x83, 0x54, 0x52, 0x45, 0xcb, 0xd4, 0x68, 0xc8, 0x43, 0x45, 0xca, 0x91, 0xfb,
                                           0xa3, 0x7a, 0x67, 0xed, 0xe8, 0xd7, 0x5e, 0xe2, 0x33, 0xd1, 0x3e, 0xbf, 0x50, 0xc2, 0x4b,
                                           0x86, 0x83, 0x55, 0x11, 0xbb, 0x17, 0x4f, 0xf5, 0x78, 0xb8, 0x65, 0xeb, 0x9a, 0x2b, 0x8f,
                                           0x77, 0x08, 0xa9, 0x60, 0x17, 0x73, 0xc5, 0x07, 0xf3, 0x04, 0xc9, 0x3f, 0x67, 0x4d, 0x12,
                                           0xa1, 0x02, 0x93, 0xc2, 0x3c, 0xd3, 0xf8, 0x59, 0x33, 0xd5, 0x01, 0xc3, 0xbb, 0xaa, 0xe6,
                                           0x3f, 0xbb, 0x23, 0x66, 0x94, 0x26, 0x28, 0x43, 0xa5, 0xfd, 0x2f};
        WOLFSSL_EVP_CIPHER_CTX *enc_ctx, *dec_ctx;
        uint8_t *encrypted, *decrypted;
        size_t tag_len, enc_len, dec_len;

        printf("   wolfSSL_quic_crypt(aes_128_gcm)");
        AssertTrue((tag_len = wolfSSL_quic_get_aead_tag_len(aead)) == 16);
        dec_len = sizeof(plaintext);
        enc_len = dec_len + tag_len;
        AssertNotNull(encrypted = XMALLOC(enc_len, NULL, DYNAMIC_TYPE_TMP_BUFFER));
        AssertNotNull(decrypted = XMALLOC(dec_len, NULL, DYNAMIC_TYPE_TMP_BUFFER));

        AssertNotNull(enc_ctx = wolfSSL_quic_crypt_new(aead, key, iv, 1));
        AssertTrue(wolfSSL_quic_aead_encrypt(encrypted, enc_ctx,
                                             plaintext, sizeof(plaintext),
                                             NULL, aad, sizeof(aad)) == WOLFSSL_SUCCESS);
        AssertTrue(memcmp(expected, encrypted, dec_len) == 0);
        AssertTrue(memcmp(expected+dec_len, encrypted+dec_len, tag_len) == 0);

        AssertNotNull(dec_ctx = wolfSSL_quic_crypt_new(aead, key, iv, 0));
        AssertTrue(wolfSSL_quic_aead_decrypt(decrypted, dec_ctx,
                                             encrypted, enc_len,
                                             NULL, aad, sizeof(aad)) == WOLFSSL_SUCCESS);
        AssertTrue(memcmp(plaintext, decrypted, dec_len) == 0);
        printf(": %s\n", (ret == 0)? passed : failed);

        XFREE(encrypted, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decrypted, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wolfSSL_EVP_CIPHER_CTX_free(enc_ctx);
        wolfSSL_EVP_CIPHER_CTX_free(dec_ctx);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    return ret;
}

typedef struct {
    const char *name;
    WOLFSSL *ssl;
    byte output[128*1024];
    size_t output_len;
    int output_level;
    byte rx_secret[4][1024];
    size_t rx_secret_len[4];
    byte tx_secret[4][1024];
    size_t tx_secret_len[4];
    int handshake_done;
    int alert_level;
    int alert;
    int flushed;
    int verbose;
    byte ticket[16*1024];
    size_t ticket_len;
} QuicTestContext;

static int ctx_set_encryption_secrets(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);
static int ctx_add_handshake_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len);
static int ctx_flush_flight(WOLFSSL *ssl);
static int ctx_send_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert);

static WOLFSSL_QUIC_METHOD ctx_method = {
    ctx_set_encryption_secrets,
    ctx_add_handshake_data,
    ctx_flush_flight,
    ctx_send_alert,
};

static void QuicTestContext_init(QuicTestContext *tctx, WOLFSSL_CTX *ctx,
                                 const char *name, int verbose)
{
    AssertNotNull(tctx);
    memset(tctx, 0, sizeof(*tctx));
    tctx->name = name;
    AssertNotNull((tctx->ssl = wolfSSL_new(ctx)));
    tctx->verbose = verbose;
    wolfSSL_set_app_data(tctx->ssl, tctx);
    AssertTrue(wolfSSL_set_quic_method(tctx->ssl, &ctx_method) == WOLFSSL_SUCCESS);
    wolfSSL_set_verify(tctx->ssl, SSL_VERIFY_NONE, 0);
}

static int ctx_set_encryption_secrets(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len)
{
    QuicTestContext *ctx = wolfSSL_get_app_data(ssl);

    WOLFSSL_ENTER("ctx_set_encryption_secrets");
    AssertNotNull(ctx);
    AssertTrue(secret_len <= sizeof(ctx->rx_secret[0]));
    if (read_secret) {
        memcpy(ctx->rx_secret[level], read_secret, secret_len);
        ctx->rx_secret_len[level] = secret_len;
    }
    if (write_secret) {
        memcpy(ctx->tx_secret[level], write_secret, secret_len);
        ctx->tx_secret_len[level] = secret_len;
    }
    AssertNotNull(ctx);
    return 1;
}

static int ctx_add_handshake_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len)
{
    QuicTestContext *ctx = wolfSSL_get_app_data(ssl);

    WOLFSSL_ENTER("ctx_add_handshake_data");
    AssertNotNull(ctx);
    ctx->output_level = level;
    printf("[%s] add_handshake[enc_level=%d]: %lu bytes\n", ctx->name, level, len);
    if (/*disables code*/(0)) {
        dump_buffer("add", data, len, 0);
    }
    if (len > 0) {
        AssertTrue(ctx->output_len + len < sizeof(ctx->output));
        memcpy(ctx->output + ctx->output_len, data, len);
        ctx->output_len += len;
    }
    return 1;
}

static int ctx_flush_flight(WOLFSSL *ssl)
{
    QuicTestContext *ctx = wolfSSL_get_app_data(ssl);

    WOLFSSL_ENTER("ctx_flush_flight");
    AssertNotNull(ctx);
    ctx->flushed = 1;
    return 1;
}

static int ctx_send_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert)
{
    QuicTestContext *ctx = wolfSSL_get_app_data(ssl);

    printf("[%s] send_alert: level=%d, alert=%d\n", ctx->name, level, alert);
    AssertNotNull(ctx);
    ctx->alert_level = level;
    ctx->alert = alert;
    return 1;
}

#ifdef HAVE_SESSION_TICKET
static int ctx_session_ticket_cb(WOLFSSL* ssl,
                                 const unsigned char* ticket, int ticketSz,
                                 void* cb_ctx)
{
    QuicTestContext *ctx = wolfSSL_get_app_data(ssl);

    (void)cb_ctx;
    memset(ctx->ticket, 0, sizeof(ctx->ticket));
    ctx->ticket_len = ticketSz;
    memcpy(ctx->ticket, ticket, sizeof(ctx->ticket) > ctx->ticket_len?
           sizeof(ctx->ticket) : ctx->ticket_len);
    if (ctx->verbose) {
        printf("Session Ticket[%s]: ticketSz = %d\n", ctx->name, ticketSz);
    }
    return 0;
}
#endif

static void ctx_dump_output(QuicTestContext *ctx)
{
    dump_buffer("Output", ctx->output, ctx->output_len, 0);
}

static void check_handshake_record(const byte *data, size_t data_len, int *ptype, size_t *prlen)
{
    word32 rlen;
    AssertTrue(data_len >= HANDSHAKE_HEADER_SZ);
    *ptype = data[0];
    c24to32(&data[1], &rlen);
    *prlen = rlen + HANDSHAKE_HEADER_SZ;
}

static void ext_dump(const byte *data, size_t data_len, int indent)
{
    size_t idx = 0;
    word16 len16, etype, i;

    printf("%*sextensions:\n", indent, " ");
    while (idx < data_len) {
        ato16(&data[idx], &etype); /* extension type */
        ato16(&data[idx+2], &len16); /* extension length */
        printf("  extension: %04x [", etype);
        for (i = 0; i < len16; ++i) {
            printf("%s0x%02x", (i? ", ": ""), data[idx+4+i]);
        }
        printf("]\n");
        idx += 2 + 2 + len16;
    }
}

static const byte *ext_find(const byte *data, size_t data_len, int ext_type)
{
    size_t idx = 0;
    word16 len16, etype;

    while (idx < data_len) {
        ato16(&data[idx], &etype); /* extension type */
        if (etype == ext_type) {
            return data + idx;
        }
        ato16(&data[idx+2], &len16); /* extension length */
        idx += 2 + 2 + len16;
    }
    return NULL;
}

static int ext_has(const byte *data, size_t data_len, int ext_type)
{
    return ext_find(data, data_len,ext_type) != NULL;
}

static void ext_equals(const byte *data, size_t data_len, int ext_type,
                       const byte *exp_data, size_t exp_len)
{
    const byte *ext;
    word16 len16;

    AssertNotNull(ext = ext_find(data, data_len, ext_type));
    ato16(&ext[2], &len16);
    AssertTrue(len16 == exp_len);
    AssertTrue(memcmp(ext + 4, exp_data, exp_len) == 0);
}

static void check_quic_client_hello(const byte *data, size_t data_len, int verbose, int indent)
{
    size_t idx;
    word16 len16;
    const byte *exts;
    size_t exts_len, rec_len;
    int rec_type;
    static byte ext_sup_version[3] = {0x02, 0x03, 0x04};

    check_handshake_record(data, data_len, &rec_type, &rec_len);
    AssertIntEQ(rec_type, client_hello);
    idx = HANDSHAKE_HEADER_SZ;
    /* the client hello arrives alone */
    AssertIntEQ(rec_len, data_len);
    AssertTrue(data[idx++] == SSLv3_MAJOR);
    AssertTrue(data[idx++] == TLSv1_2_MINOR);
    idx += 32; /* 32 bytes RANDOM */
    /*AssertIntEQ(data[idx], 0);  session id 0 len? */
    idx += 1 + data[idx];
    ato16(&data[idx], &len16); /* ciphers length */
    AssertTrue(len16 > 0);
    idx += 2 + len16;
    AssertTrue(data[idx] == 1);   /* compressions */
    AssertTrue(data[idx+1] == 0);   /* no compression */
    idx += 2;
    ato16(&data[idx], &len16); /* extensions length */
    AssertTrue(len16 > 0);
    exts_len = len16;
    idx += 2;
    exts = &data[idx];
    idx += exts_len;
    AssertTrue(idx <= rec_len); /* should fit */
    for (; idx < rec_len; ++idx) {
        AssertTrue(data[idx] == 0); /* padding */
    }
    ext_equals(exts, exts_len, TLSX_SUPPORTED_VERSIONS,
               ext_sup_version, sizeof(ext_sup_version));
    if (verbose) {
        ext_dump(exts, exts_len, indent);
        dump_buffer("", data, data_len, indent);
    }
}

static void check_quic_client_hello_tp(const byte *data, size_t data_len,
        int tp_v1, int tp_draft)
{
    size_t idx;
    word16 len16;
    const byte *exts;
    size_t exts_len, rec_len;
    int rec_type;

    check_handshake_record(data, data_len, &rec_type, &rec_len);
    AssertIntEQ(rec_type, client_hello);
    idx = HANDSHAKE_HEADER_SZ;
    idx += 2; /* old version */
    idx += 32; /* 32 bytes RANDOM */
    idx += 1 + data[idx]; /* session id */
    ato16(&data[idx], &len16); /* ciphers length */
    idx += 2 + len16;
    idx += 2; /* compression */
    ato16(&data[idx], &len16); /* extensions length */
    AssertTrue(len16 > 0);
    exts_len = len16;
    idx += 2;
    exts = &data[idx];

    AssertTrue(!ext_has(exts, exts_len, TLSX_KEY_QUIC_TP_PARAMS) == !tp_v1);
    AssertTrue(!ext_has(exts, exts_len, TLSX_KEY_QUIC_TP_PARAMS_DRAFT) == !tp_draft);
}

static void check_secrets(QuicTestContext *ctx, int level, size_t rx_len, size_t tx_len)
{
    AssertTrue(level < 4);
    AssertIntEQ(ctx->rx_secret_len[level], rx_len);
    AssertIntEQ(ctx->tx_secret_len[level], tx_len);
}

static void assert_secrets_EQ(QuicTestContext *ctx1, QuicTestContext *ctx2, int level)
{
    /* rx secrets are the other ones tx secrets */
    AssertIntEQ(ctx1->rx_secret_len[level], ctx2->tx_secret_len[level]);
    AssertIntEQ(ctx1->tx_secret_len[level], ctx2->rx_secret_len[level]);
    AssertIntEQ(memcmp(ctx1->rx_secret[level], ctx2->tx_secret[level], ctx1->rx_secret_len[level]), 0);
    AssertIntEQ(memcmp(ctx1->tx_secret[level], ctx2->rx_secret[level], ctx1->tx_secret_len[level]), 0);
}

static int test_quic_client_hello(void) {
    WOLFSSL_CTX *ctx;
    int ret = 0, verbose = 0;
    QuicTestContext tctx;
    const byte tp_params[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    (void)ctx_dump_output;

    AssertNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));

    printf("   quic client_hello(no tp set)");
    QuicTestContext_init(&tctx, ctx, "client", verbose);
    AssertTrue(wolfSSL_quic_read_write(tctx.ssl) != 0);
    /* Since we have not set any QUIC transport params, and they are
     * mandatory, this needs to fail */
    AssertIntEQ(wolfSSL_get_error(tctx.ssl, 0), QUIC_TP_MISSING_E);
    wolfSSL_free(tctx.ssl);
    printf(": %s\n", (ret == 0)? passed : failed);

    /* Set transport params, expect both extensions */
    printf("   quic client_hello(tp set)");
    QuicTestContext_init(&tctx, ctx, "client", verbose);
    wolfSSL_UseSessionTicket(tctx.ssl);
    wolfSSL_set_tlsext_host_name(tctx.ssl, "wolfssl.com");
    wolfSSL_set_quic_transport_params(tctx.ssl, tp_params, sizeof(tp_params));
    AssertTrue(wolfSSL_connect(tctx.ssl) != 0);
    AssertIntEQ(wolfSSL_get_error(tctx.ssl, 0), SSL_ERROR_WANT_READ);
    check_quic_client_hello_tp(tctx.output, tctx.output_len, 1, 1);
    wolfSSL_free(tctx.ssl);
    printf(": %s\n", (ret == 0)? passed : failed);

    /* Set transport params v1, expect v1 extension */
    printf("   quic client_hello(tp set v1)");
    QuicTestContext_init(&tctx, ctx, "client", verbose);
    wolfSSL_set_quic_transport_version(tctx.ssl, TLSX_KEY_QUIC_TP_PARAMS);
    wolfSSL_set_quic_transport_params(tctx.ssl, tp_params, sizeof(tp_params));
    AssertTrue(wolfSSL_connect(tctx.ssl) != 0);
    check_quic_client_hello_tp(tctx.output, tctx.output_len, 1, 0);
    wolfSSL_free(tctx.ssl);
    printf(": %s\n", (ret == 0)? passed : failed);

    /* Set transport params draft, expect draft extension */
    printf("   quic client_hello(tp set draft)");
    QuicTestContext_init(&tctx, ctx, "client", verbose);
    wolfSSL_set_quic_transport_version(tctx.ssl, TLSX_KEY_QUIC_TP_PARAMS_DRAFT);
    wolfSSL_set_quic_transport_params(tctx.ssl, tp_params, sizeof(tp_params));
    AssertTrue(wolfSSL_connect(tctx.ssl) != 0);
    check_quic_client_hello_tp(tctx.output, tctx.output_len, 0, 1);
    wolfSSL_free(tctx.ssl);
    printf(": %s\n", (ret == 0)? passed : failed);

    /* Set transport params 0, expect both extension */
    printf("   quic client_hello(tp set both)");
    QuicTestContext_init(&tctx, ctx, "client", verbose);
    wolfSSL_set_quic_transport_version(tctx.ssl, 0);
    wolfSSL_set_quic_transport_params(tctx.ssl, tp_params, sizeof(tp_params));
    AssertTrue(wolfSSL_connect(tctx.ssl) != 0);
    check_quic_client_hello_tp(tctx.output, tctx.output_len, 1, 1);
    wolfSSL_free(tctx.ssl);
    printf(": %s\n", (ret == 0)? passed : failed);

    wolfSSL_CTX_free(ctx);

    return ret;
}

static void check_ee(const byte *data, size_t data_len, int verbose, int indent)
{
    size_t rec_len, exts_len, idx;
    word16 len16;
    const byte *exts;
    int rec_type;

    check_handshake_record(data, data_len, &rec_type, &rec_len);
    AssertIntEQ(rec_type, encrypted_extensions);
    idx = HANDSHAKE_HEADER_SZ;
    ato16(&data[idx], &len16); /* extensions length */
    AssertTrue(len16 > 0);
    exts_len = len16;
    idx += 2;
    exts = &data[idx];
    if (verbose) {
        ext_dump(exts, exts_len, indent);
    }
}

static void check_quic_server_hello(const byte *data, size_t data_len, int verbose, int indent)
{
    size_t idx;
    word16 len16, cipher;
    const byte *exts;
    size_t exts_len, rec_len;
    static byte ext_sup_version[2] = {0x03, 0x04};
    int rec_type;

    check_handshake_record(data, data_len, &rec_type, &rec_len);
    AssertIntEQ(rec_type, server_hello);
    idx = HANDSHAKE_HEADER_SZ;
    AssertTrue(data[idx++] == SSLv3_MAJOR);
    AssertTrue(data[idx++] == TLSv1_2_MINOR);
    idx += 32; /* 32 bytes RANDOM */
    /* AssertIntEQ(data[idx], 0);  session id of len 0 */
    idx += 1 + data[idx];
    ato16(&data[idx], &cipher); /* cipher selected */
    AssertTrue(cipher != 0);
    idx += 2;
    AssertTrue(data[idx] == 0);   /* null compression */
    idx += 1;
    ato16(&data[idx], &len16); /* extensions length */
    AssertTrue(len16 > 0);
    exts_len = len16;
    idx += 2;
    exts = &data[idx];
    idx += exts_len;
    AssertTrue(idx <= rec_len); /* should fit */
    for (; idx < rec_len; ++idx) {
        AssertTrue(data[idx] == 0); /* padding */
    }
    if (verbose) {
        ext_dump(exts, exts_len, indent);
        dump_buffer("", data, rec_len, indent);
    }
    ext_equals(exts, exts_len, TLSX_SUPPORTED_VERSIONS,
               ext_sup_version, sizeof(ext_sup_version));
}

static void check_crypto_rec(const byte *data, size_t data_len, int verbose, int indent)
{
    size_t rec_len;
    int rec_type;

    check_handshake_record(data, data_len, &rec_type, &rec_len);
    if (verbose) {
        dump_buffer("", data, rec_len, indent);
    }
}

static void check_crypto_records(QuicTestContext *from, int indent, char *rec_log)
{
    const byte *data = from->output;
    size_t data_len = from->output_len;
    size_t rec_len;
    int rec_type;
    const char *rec_name;
    char buffer[128];
    void (*check_rec) (const byte *d, size_t l, int v, int indent);

    while (data_len > 0) {
        check_handshake_record(data, data_len, &rec_type, &rec_len);
        AssertTrue(rec_len <= data_len);
        check_rec = check_crypto_rec;
        switch (rec_type) {
            case client_hello:
                rec_name = "ClientHello";
                check_rec = check_quic_client_hello;
                break;
            case server_hello:
                rec_name = "ServerHello";
                check_rec = check_quic_server_hello;
                break;
            case session_ticket:
                rec_name = "SessionTicket";
                break;
            case encrypted_extensions:
                rec_name = "EncryptedExtension";
                check_rec = check_ee;
                break;
            case certificate:
                rec_name = "Certificate";
                break;
            case certificate_verify:
                rec_name = "CertificateVerify";
                break;
            case finished:
                rec_name = "Finished";
                break;
            default:
                sprintf(buffer, "%d", rec_type);
                rec_name = buffer;
                break;
        }

        if (rec_log) {
            if (*rec_log) strcat(rec_log, ":");
            strcat(rec_log, rec_name);
        }
        printf("%*sCRYPTO[%s]: ", indent, " ", rec_name);
        check_rec(data, rec_len, from->verbose, indent);
        printf("\n");
        data += rec_len;
        data_len -= rec_len;
    }
}

static void QuicTestContext_forward(QuicTestContext *from, QuicTestContext *to, char *rec_log)
{
    int ret;

    if (from->output_len > 0) {
        if (from->verbose) {
            printf("[%s -> %s] forward %lu bytes at level %d\n",
                   from->name, to->name, from->output_len, from->output_level);
        }
        check_crypto_records(from, 4, rec_log);
        ret = wolfSSL_provide_quic_data(to->ssl, from->output_level, from->output, from->output_len);
        from->output_len = 0;
        AssertIntEQ(ret, WOLFSSL_SUCCESS);
    }
}

typedef struct {
    QuicTestContext *client;
    QuicTestContext *server;
    int started;
    char rec_log[16*1024];
} QuicConversation;

static void QuicConversation_init(QuicConversation *conv,
                                  QuicTestContext *tclient, QuicTestContext *tserver)
{
    memset(conv, 0, sizeof(*conv));
    conv->client = tclient;
    conv->server = tserver;
}

static int QuicConversation_step(QuicConversation *conv)
{
    int n;

    if (!conv->started) {
        AssertTrue(wolfSSL_connect(conv->client->ssl) != WOLFSSL_SUCCESS);
        AssertIntEQ(SSL_ERROR_WANT_READ, wolfSSL_get_error(conv->client->ssl, 0));
        conv->started = 1;
    }
    if (conv->server->output_len > 0) {
        QuicTestContext_forward(conv->server, conv->client, conv->rec_log);
        n = wolfSSL_quic_read_write(conv->client->ssl);
        if (n != WOLFSSL_SUCCESS) {
            AssertIntEQ(wolfSSL_get_error(conv->client->ssl, 0), SSL_ERROR_WANT_READ);
        }
        return 1;
    }
    else if (conv->client->output_len > 0) {
        QuicTestContext_forward(conv->client, conv->server, conv->rec_log);
        n = wolfSSL_quic_read_write(conv->server->ssl);
        if (n != WOLFSSL_SUCCESS) {
            AssertIntEQ(wolfSSL_get_error(conv->client->ssl, 0), SSL_ERROR_WANT_READ);
        }
        return 1;
    }
    return 0;
}

static void QuicConversation_do(QuicConversation *conv)
{
    if (!conv->started) {
        AssertTrue(wolfSSL_connect(conv->client->ssl) != WOLFSSL_SUCCESS);
        AssertIntEQ(SSL_ERROR_WANT_READ, wolfSSL_get_error(conv->client->ssl, 0));
        conv->started = 1;
    }
    while (1) {
        if (!QuicConversation_step(conv)) {
            if (wolfSSL_get_error(conv->client->ssl, 0) == 0
                && wolfSSL_get_error(conv->server->ssl, 0) == 0) {
                break;  /* handshake done */
            }
            AssertNull("Neither tclient nor server have anything to send, "
                "but handshake has not concluded");
        }
    }
}

static int test_quic_server_hello(void) {
    WOLFSSL_CTX *ctx_c, *ctx_s;
    int ret = 0, verbose = 1;
    QuicTestContext tclient, tserver;
    QuicConversation conv;
    const byte tp_params_c[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    const byte tp_params_s[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    WOLFSSL_SESSION *session;

    AssertNotNull(ctx_c = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    wolfSSL_CTX_UseSessionTicket(ctx_c);

    AssertNotNull(ctx_s = wolfSSL_CTX_new(wolfTLSv1_3_server_method()));
    AssertTrue(wolfSSL_CTX_use_certificate_file(ctx_s, svrCertFile, WOLFSSL_FILETYPE_PEM));
    AssertTrue(wolfSSL_CTX_use_PrivateKey_file(ctx_s, svrKeyFile, WOLFSSL_FILETYPE_PEM));

    /* setup client ssl */
    QuicTestContext_init(&tclient, ctx_c, "client", verbose);
    wolfSSL_set_quic_transport_version(tclient.ssl, 0);
    wolfSSL_set_quic_transport_params(tclient.ssl, tp_params_c, sizeof(tp_params_c));
#ifdef HAVE_SESSION_TICKET
    wolfSSL_set_SessionTicket_cb(tclient.ssl, ctx_session_ticket_cb, NULL);
#endif
    /* setup server ssl */
    AssertNotNull(tserver.ssl = wolfSSL_new(ctx_s));
    QuicTestContext_init(&tserver, ctx_s, "server", verbose);
    wolfSSL_set_quic_transport_version(tserver.ssl, 0);
    wolfSSL_set_quic_transport_params(tserver.ssl, tp_params_s, sizeof(tp_params_s));

    /* connect */
    QuicConversation_init(&conv, &tclient, &tserver);
    QuicConversation_step(&conv);
    /* check established/missing secrets */
    check_secrets(&tserver, wolfssl_encryption_initial, 0, 0);
    check_secrets(&tserver, wolfssl_encryption_handshake, 32, 32);
    check_secrets(&tserver, wolfssl_encryption_application, 32, 32);
    check_secrets(&tclient, wolfssl_encryption_handshake, 0, 0);
    /* feed the server data to the client */
    QuicConversation_step(&conv);
    /* client has generated handshake secret */
    check_secrets(&tclient, wolfssl_encryption_handshake, 32, 32);
    /* continue the handshake till done */
    conv.started = 1;
    /* run till end */
    QuicConversation_do(&conv);
    AssertIntEQ(tclient.output_len, 0);
    AssertIntEQ(tserver.output_len, 0);
    /* what have we seen? */
    AssertStrEQ(conv.rec_log, "ClientHello:ServerHello:EncryptedExtension:Certificate:CertificateVerify:Finished:Finished:SessionTicket");
    /* we are at application encryption level */
    AssertIntEQ(wolfSSL_quic_read_level(tclient.ssl), wolfssl_encryption_application);
    AssertIntEQ(wolfSSL_quic_write_level(tclient.ssl), wolfssl_encryption_application);
    AssertIntEQ(wolfSSL_quic_read_level(tserver.ssl), wolfssl_encryption_application);
    AssertIntEQ(wolfSSL_quic_write_level(tserver.ssl), wolfssl_encryption_application);
    /* the last client write (FINISHED) was at handshake level */
    AssertIntEQ(tclient.output_level, wolfssl_encryption_handshake);
    /* we have the app secrets */
    check_secrets(&tclient, wolfssl_encryption_application, 32, 32);
    check_secrets(&tserver, wolfssl_encryption_application, 32, 32);
    /* verify client and server have the same secrets establishd */
    assert_secrets_EQ(&tclient, &tserver, wolfssl_encryption_handshake);
    assert_secrets_EQ(&tclient, &tserver, wolfssl_encryption_application);
    /* AEAD cipher should be known */
    AssertNotNull(wolfSSL_quic_get_aead(tclient.ssl));
    AssertNotNull(wolfSSL_quic_get_aead(tserver.ssl));

#ifdef HAVE_SESSION_TICKET
    /* Should have received a session ticket */
    AssertTrue(tclient.ticket_len > 0);
    AssertNotNull(session = wolfSSL_get1_session(tclient.ssl));
    wolfSSL_free(tclient.ssl);
    wolfSSL_free(tserver.ssl);

    /* Do a Session resumption with the ticket */
    AssertNotNull(tserver.ssl = wolfSSL_new(ctx_s));
    QuicTestContext_init(&tserver, ctx_s, "server", verbose);
    wolfSSL_set_quic_transport_version(tserver.ssl, 0);
    wolfSSL_set_quic_transport_params(tserver.ssl, tp_params_s, sizeof(tp_params_s));
    /* setup client with last session */
    QuicTestContext_init(&tclient, ctx_c, "client", verbose);
    wolfSSL_set_quic_transport_version(tclient.ssl, 0);
    wolfSSL_set_quic_transport_params(tclient.ssl, tp_params_c, sizeof(tp_params_c));
    wolfSSL_set_SessionTicket_cb(tclient.ssl, ctx_session_ticket_cb, NULL);
    AssertIntEQ(wolfSSL_set_session(tclient.ssl, session), WOLFSSL_SUCCESS);
    /* let them talk */
    QuicConversation_init(&conv, &tclient, &tserver);
    QuicConversation_do(&conv);
    /* this is what should happen. Look Ma, no certificate! */
    AssertStrEQ(conv.rec_log, "ClientHello:ServerHello:EncryptedExtension:Finished:Finished:SessionTicket");
#endif

    wolfSSL_free(tclient.ssl);
    wolfSSL_free(tserver.ssl);

    wolfSSL_SESSION_free(session);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);

    return ret;
}
#endif /* WOLFSSL_QUIC */

int QuicTest(void)
{
    int ret = 0;
#ifdef WOLFSSL_QUIC
    printf(" Begin QUIC Tests\n");

    if ((ret = test_set_quic_method()) != 0) goto leave;
    if ((ret = test_provide_quic_data()) != 0) goto leave;
    if ((ret = test_quic_crypt()) != 0) goto leave;
    if ((ret = test_quic_client_hello()) != 0) goto leave;
    if ((ret = test_quic_server_hello()) != 0) goto leave;

leave:
    if (ret == 0)
        printf("\n Success -- All results as expected.\n");
    printf(" End QUIC Tests\n");
#endif
    return ret;
}
