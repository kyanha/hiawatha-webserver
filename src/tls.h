/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _TLS_H
#define _TLS_H

#include "config.h"

#ifdef ENABLE_TLS

#include <stdbool.h>
#include "liblist.h"
#include "polarssl/ssl.h"
#include "polarssl/x509.h"
#include "polarssl/version.h"

#define TLS_HANDSHAKE_OKE       0
#define TLS_HANDSHAKE_ERROR    -1
#define TLS_HANDSHAKE_TIMEOUT  -2
#define TLS_HANDSHAKE_NO_MATCH -3

typedef struct {
	ssl_context *context;
	int         *client_fd;
	pk_context  *private_key;
	x509_crt    *certificate;
	x509_crt    *ca_certificate;
	x509_crl    *ca_crl;
	int         timeout;
	int         min_tls_version;
	int         dh_size;
#ifdef ENABLE_DEBUG
	int         thread_id;
#endif
} t_tls_accept_data;

#ifdef ENABLE_DEBUG
int  init_tls_module(x509_crt *ca_certs, char *logfile);
#else
int  init_tls_module(x509_crt *ca_certs);
#endif
#if POLARSSL_VERSION_NUMBER >= 0x01020000
int  tls_register_sni(t_charlist *hostname, pk_context *private_key, x509_crt *certificate,
                  x509_crt *ca_certificate, x509_crl *ca_crl);
#endif
int  tls_load_key_cert(char *file, pk_context **private_key, x509_crt **certificate);
int  tls_load_ca_cert(char *file, x509_crt **ca_certificate);
int  tls_load_ca_crl(char *file, x509_crl **ca_crl);
int  tls_load_ca_root_certs(char *source, x509_crt **ca_root_certs);
int  tls_accept(t_tls_accept_data *tls_accept_data);
int  tls_pending(ssl_context *ssl);
int  tls_receive(ssl_context *ssl, char *buffer, unsigned int maxlength);
int  tls_send(ssl_context *ssl, const char *buffer, unsigned int length);
bool tls_has_peer_cert(ssl_context *context);
int  tls_get_peer_cert_info(ssl_context *context, char *subject_dn, char *issuer_dn, char *serial_nr, int length);
char *tls_version_string(ssl_context *context);
char *tls_cipher_string(ssl_context *context);
void tls_close(ssl_context *ssl);
void tls_shutdown(void);
int  tls_connect(ssl_context *ssl, int *sock, char *hostname);
int  tls_send_buffer(ssl_context *ssl, const char *buffer, int size);

#endif

#endif
