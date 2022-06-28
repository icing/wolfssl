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
    (void)level;
    (void)read_secret;
    (void)write_secret;
    (void)secret_len;
    return 1;
}

static int dummy_add_handshake_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                    const uint8_t *data, size_t len)
{
    (void)ssl;
    (void)level;
    (void)data;
    (void)len;
    return 1;
}

static int dummy_flush_flight(WOLFSSL *ssl)
{
    (void)ssl;
    return 1;
}

static int dummy_send_alert(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert)
{
    (void)ssl;
    (void)level;
    (void)alert;
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
        /* TODO: Not sure, if the initial 0 is really what is expected */
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == 0);
        wolfSSL_set_quic_transport_version(ssl, WOLFSSL_TLSEXT_QUIC_TP_PARAMS);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == WOLFSSL_TLSEXT_QUIC_TP_PARAMS);
        wolfSSL_set_quic_use_legacy_codepoint(ssl, 1);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == WOLFSSL_TLSEXT_QUIC_TP_PARAMS_DRAFT);
        wolfSSL_set_quic_use_legacy_codepoint(ssl, 0);
        AssertTrue(wolfSSL_get_quic_transport_version(ssl) == WOLFSSL_TLSEXT_QUIC_TP_PARAMS);
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
        AssertFalse(wolfSSL_set_quic_transport_params(ssl, NULL, 0) == WOLFSSL_SUCCESS);
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

static void dump_buffers(WOLFSSL *ssl, FILE *fp)
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
        dump_buffers(ssl, stdout);
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


#endif /* WOLFSSL_QUIC */


int QuicTest(void)
{
    int ret = 0;
#ifdef WOLFSSL_QUIC
    printf(" Begin QUIC Tests\n");

    if ((ret = test_set_quic_method()) != 0) goto leave;
    if ((ret = test_provide_quic_data()) != 0) goto leave;

leave:
    if (ret == 0)
        printf("\n Success -- All results as expected.\n");
    printf(" End QUIC Tests\n");
#endif
    return ret;
}
