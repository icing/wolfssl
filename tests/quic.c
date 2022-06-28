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
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>

#ifdef WOLFSSL_QUIC

#define testingFmt "   %s:"
#define resultFmt  " %s\n"
static const char* passed = "passed";
static const char* failed = "failed";

typedef struct {
    const char *name;
    WOLFSSL_METHOD *method;
    int is_server;
} ctx_setups;

static int test_set_quic_method(void) {
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    int ret = 0, i;
    WOLFSSL_QUIC_METHOD qmethod = { NULL, NULL, NULL, NULL };
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
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertFalse(wolfSSL_is_quic(ssl));

        AssertTrue(wolfSSL_set_quic_method(ssl, &qmethod) == WOLFSSL_SUCCESS);
        AssertTrue(wolfSSL_is_quic(ssl));
        wolfSSL_free(ssl);

        AssertTrue(wolfSSL_CTX_set_quic_method(ctx, &qmethod) == WOLFSSL_SUCCESS);
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertTrue(wolfSSL_is_quic(ssl));
        wolfSSL_free(ssl);

        AssertTrue(wolfSSL_CTX_set_quic_method(ctx, NULL) == WOLFSSL_SUCCESS);
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertFalse(wolfSSL_is_quic(ssl));
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
        AssertFalse(wolfSSL_CTX_set_quic_method(ctx, &qmethod) == WOLFSSL_SUCCESS);
        AssertNotNull(ssl = wolfSSL_new(ctx));
        AssertFalse(wolfSSL_set_quic_method(ssl, &qmethod) == WOLFSSL_SUCCESS);
        AssertFalse(wolfSSL_is_quic(ssl));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        printf(": %s\n", (ret == 0)? passed : failed);
    }

    return ret;
}

#endif /* WOLFSSL_QUIC */


int QuicTest(void)
{
    int ret = 0;
#ifdef WOLFSSL_QUIC
    printf(" Begin QUIC Tests\n");

    if ((ret = test_set_quic_method()) != 0) goto leave;

leave:
    if (ret == 0)
        printf("\n Success -- All results as expected.\n");
    printf(" End QUIC Tests\n");
#endif
    return ret;
}
