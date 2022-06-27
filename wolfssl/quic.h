/* quic.h
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



/* wolfSSL QUIC API */

#ifndef WOLFSSL_QUIC_H
#define WOLFSSL_QUIC_H

#ifdef WOLFSSL_QUIC

/* QUIC operates on three encryption levels which determine
 * which keys/algos are used for de-/encryption. These are
 * kept separately for incoming and outgoing data and.
 * Due to the nature of UDP, more than one might be in use
 * at the same time due to resends or out-of-order arrivals.
 */
typedef enum wolfssl_encryption_level_t {
    wolfssl_encryption_initial = 0,
    wolfssl_encryption_early_data,
    wolfssl_encryption_handshake,
    wolfssl_encryption_application
} WOLFSSL_ENCRYPTION_LEVEL;


/* All QUIC related callbacks to the application.
 */
typedef struct wolfssl_quic_method_t WOLFSSL_QUIC_METHOD;

struct wolfssl_quic_method_t {
    int (*set_encryption_secrets)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len);
    int (*add_handshake_data)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len);
    int (*flush_flight)(WOLFSSL *ssl);
    int (*send_alert)(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level, uint8_t alert);
};


WOLFSSL_API int wolfSSL_CTX_set_quic_method(WOLFSSL_CTX *ctx,
                                            const WOLFSSL_QUIC_METHOD *quic_method);
WOLFSSL_API int wolfSSL_set_quic_method(WOLFSSL *ssl,
                                        const WOLFSSL_QUIC_METHOD *quic_method);
WOLFSSL_API int wolfSSL_is_quic(WOLFSSL *ssl);

WOLFSSL_API WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_read_level(const WOLFSSL *ssl);
WOLFSSL_API WOLFSSL_ENCRYPTION_LEVEL wolfSSL_quic_write_level(const WOLFSSL *ssl);


WOLFSSL_API int wolfSSL_set_quic_transport_params(WOLFSSL *ssl,
                                                  const uint8_t *params,
                                                  size_t params_len);
WOLFSSL_API void SSL_get_peer_quic_transport_params(const WOLFSSL *ssl,
                                                    const uint8_t **out_params,
                                                    size_t *out_params_len);


WOLFSSL_API size_t wolfSSL_quic_max_handshake_flight_len(const WOLFSSL *ssl,
                                                         WOLFSSL_ENCRYPTION_LEVEL level);


WOLFSSL_API int wolfSSL_CIPHER_get_prf_nid(const WOLFSSL_CIPHER *c);

enum {
    WOLFSSL_TLSEXT_QUIC_TP_PARAMS_DRAFT = 0xffa5,  /* value from draft-ietf-quic-tls-27 */
    WOLFSSL_TLSEXT_QUIC_TP_PARAMS = 0x0039,        /* rfc9001, ch. 8.2 */
};

WOLFSSL_API void wolfSSL_set_quic_use_legacy_codepoint(WOLFSSL *ssl, int use_legacy);
WOLFSSL_API void wolfSSL_set_quic_transport_version(WOLFSSL *ssl, int version);
WOLFSSL_API int wolfSSL_get_quic_transport_version(const WOLFSSL *ssl);


WOLFSSL_API int wolfSSL_provide_quic_data(WOLFSSL *ssl, WOLFSSL_ENCRYPTION_LEVEL level,
                                          const uint8_t *data, size_t len);

WOLFSSL_API int wolfSSL_process_quic_post_handshake(WOLFSSL *ssl);

#ifdef WOLFSSL_EARLY_DATA
WOLFSSL_API void wolfSSL_set_quic_early_data_enabled(WOLFSSL *ssl, int enabled);
#endif

#endif /* WOLFSSL_QUIC */
#endif /* WOLFSSL_QUIC_H */
