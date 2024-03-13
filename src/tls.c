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

#include "config.h"

#ifdef ENABLE_TLS

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/socket.h>
#include "alternative.h"
#include "tls.h"
#include "libstr.h"
#include "log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/psa_util.h"
#ifdef ENABLE_DEBUG
#include "mbedtls/debug.h"
#endif
#include "memdbg.h"

#if !defined(MBEDTLS_THREADING_PTHREAD) || !defined(MBEDTLS_THREADING_C)
#error "The mbed TLS library must be compiled with MBEDTLS_THREADING_PTHREAD and MBEDTLS_THREADING_C enabled."
#endif

#define TIMESTAMP_SIZE          40
#define SNI_MAX_HOSTNAME_LEN   128
#define PK_DER_BUFFER_SIZE    2048
#ifdef ENABLE_DEBUG
#define TLS_DEBUG_LEVEL          6
#endif

typedef struct type_sni_list {
	t_charlist *hostname;
	mbedtls_pk_context *private_key;
	mbedtls_x509_crt *certificate;
	mbedtls_x509_crt *ca_certificate;
	mbedtls_x509_crl *ca_crl;

	struct type_sni_list *next;
} t_sni_list;

static int ciphersuites[] = {
//	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
//	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
//	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	0
};

static pthread_mutex_t random_mutex;
static pthread_mutex_t cache_mutex;
static mbedtls_ssl_cache_context cache;
static t_sni_list *sni_list = NULL;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static mbedtls_ssl_config client_config;

/* Required to use random number generator functions in a multithreaded application
 */
static int tls_random(void *p_rng, unsigned char *output, size_t len) {
	int result;

	pthread_mutex_lock(&random_mutex);
	result = mbedtls_ctr_drbg_random(p_rng, output, len);
	pthread_mutex_unlock(&random_mutex);

	return result;
}

/* TLS debug callback function
 */
#ifdef ENABLE_DEBUG
static void tls_debug(void *ctx, int level, const char *file, int line, const char *str) {
	/* prevent unused warning */
	(void)ctx;

	log_string(TLS_ERROR_LOGFILE, "mbed TLS (%d) %s,%04d: %s", level, file, line, str);
}
#endif

/* Server Name Indication callback function
 */
static int sni_callback(void *param, mbedtls_ssl_context *context, const unsigned char *sni_hostname, size_t len) {
	char hostname[SNI_MAX_HOSTNAME_LEN + 1];
	t_sni_list *sni;
	int i;

	/* prevent unused warning */
	(void)param;

	if (len > SNI_MAX_HOSTNAME_LEN) {
		return -1;
	}

	memcpy(hostname, sni_hostname, len);
	hostname[len] = '\0';

	sni = sni_list;
	while (sni != NULL) {
		for (i = 0; i < sni->hostname->size; i++) {
			if (hostname_match(hostname, *(sni->hostname->item + i))) {
				/* Set private key and certificate
				 */
				if ((sni->private_key != NULL) && (sni->certificate != NULL)) {
					mbedtls_ssl_set_hs_own_cert(context, sni->certificate, sni->private_key);
				}

				/* Set CA certificate for TLS client authentication
				 */
				if (sni->ca_certificate != NULL) {
					mbedtls_ssl_set_hs_authmode(context, MBEDTLS_SSL_VERIFY_REQUIRED);
					mbedtls_ssl_set_hs_ca_chain(context, sni->ca_certificate, sni->ca_crl);
				}

				return 0;
			}
		}

		sni = sni->next;
	}

	return 0;
}

/* Initialize TLS library
 */
int init_tls_module(mbedtls_x509_crt *ca_certificates) {
	char version[16];

	if (mbedtls_version_get_number() < 0x03000000) {
		mbedtls_version_get_string(version);
		fprintf(stderr, "This Hiawatha installation requires at least mbed TLS v3.0.0 and you have v%s.\n", version);
		return -1;
	}

	if (mbedtls_version_check_feature("MBEDTLS_THREADING_PTHREAD") != 0) {
		fprintf(stderr, "mbed TLS was compiled without the required MBEDTLS_THREADING_PTHREAD compiler flag.\n");
		return -1;
	}

#ifdef ENABLE_DEBUG
	mbedtls_debug_set_threshold(TLS_DEBUG_LEVEL);
#endif

	/* Entropy settings
	 */
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)"Hiawatha_RND", 10) != 0) {
		return -1;
	}
	mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);

	/* Cache settings
	 */
	mbedtls_ssl_cache_init(&cache);
	mbedtls_ssl_cache_set_max_entries(&cache, 100);

	/* Client SSL configuratiomn
	 */
	mbedtls_ssl_config_init(&client_config);
	if (mbedtls_ssl_config_defaults(&client_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		return -1;
	}
	mbedtls_ssl_conf_renegotiation(&client_config, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(&client_config, tls_random, &ctr_drbg);
#ifdef ENABLE_DEBUG
	mbedtls_ssl_conf_dbg(&client_config, tls_debug, &client_config);
#endif

	if (ca_certificates == NULL) {
		mbedtls_ssl_conf_authmode(&client_config, MBEDTLS_SSL_VERIFY_NONE);
	} else {
		mbedtls_ssl_conf_authmode(&client_config, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&client_config, ca_certificates, NULL);
	}

	if (pthread_mutex_init(&random_mutex, NULL) != 0) {
		return -1;
	} else if (pthread_mutex_init(&cache_mutex, NULL) != 0) {
		return -1;
	}

	return 0;
}

/* Set TLS configuration
 */
int tls_set_config(mbedtls_ssl_config **tls_config, t_tls_setup *tls_setup) {
//	psa_status_t psa_status;

	if ((*tls_config = (mbedtls_ssl_config*)malloc(sizeof(mbedtls_ssl_config))) == NULL) {
		return -1;
	}

	mbedtls_ssl_config_init(*tls_config);
	if (mbedtls_ssl_config_defaults(*tls_config, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		return -1;
	}

	mbedtls_ssl_conf_min_tls_version(*tls_config, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(*tls_config, MBEDTLS_SSL_VERSION_TLS1_2);

	mbedtls_ssl_conf_renegotiation(*tls_config, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_rng(*tls_config, tls_random, &ctr_drbg);
	mbedtls_ssl_conf_sni(*tls_config, sni_callback, NULL);
	mbedtls_ssl_conf_session_cache(*tls_config, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#ifdef ENABLE_DEBUG
	mbedtls_ssl_conf_dbg(*tls_config, tls_debug, &tls_config);
#endif

	mbedtls_ssl_conf_ciphersuites(*tls_config, ciphersuites);

	if (tls_setup->ca_certificate == NULL) {
		mbedtls_ssl_conf_authmode(*tls_config, MBEDTLS_SSL_VERIFY_NONE);
	} else {
		mbedtls_ssl_conf_authmode(*tls_config, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(*tls_config, tls_setup->ca_certificate, tls_setup->ca_crl);
	}

	mbedtls_ssl_conf_own_cert(*tls_config, tls_setup->certificate, tls_setup->private_key);

	if (tls_setup->dh_size == 2048) {
		const unsigned char dhm_p[] = MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
		const unsigned char dhm_g[] = MBEDTLS_DHM_RFC7919_FFDHE2048_G_BIN;
		mbedtls_ssl_conf_dh_param_bin(*tls_config, dhm_p, sizeof(dhm_p), dhm_g, sizeof(dhm_g));
	} else if (tls_setup->dh_size == 4096) {
		const unsigned char dhm_p[] = MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
		const unsigned char dhm_g[] = MBEDTLS_DHM_RFC7919_FFDHE4096_G_BIN;
		mbedtls_ssl_conf_dh_param_bin(*tls_config, dhm_p, sizeof(dhm_p), dhm_g, sizeof(dhm_g));
	} else if (tls_setup->dh_size == 8192) {
		const unsigned char dhm_p[] = MBEDTLS_DHM_RFC7919_FFDHE8192_P_BIN;
		const unsigned char dhm_g[] = MBEDTLS_DHM_RFC7919_FFDHE8192_G_BIN;
		mbedtls_ssl_conf_dh_param_bin(*tls_config, dhm_p, sizeof(dhm_p), dhm_g, sizeof(dhm_g));
	}

/*
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS) {
		mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n", (int)psa_status);
		return -1;
	}
*/

	return 0;
}

/* Add SNI information to list
 */
int tls_register_sni(t_charlist *hostname, t_tls_setup *tls_setup) {
	t_sni_list *sni, *last;

	if ((sni = (t_sni_list*)malloc(sizeof(t_sni_list))) == NULL) {
		return -1;
	}

	sni->hostname = hostname;
	sni->private_key = tls_setup->private_key;
	sni->certificate = tls_setup->certificate;
	sni->ca_certificate = tls_setup->ca_certificate;
	sni->ca_crl = tls_setup->ca_crl;
	sni->next = NULL;

	if (sni_list == NULL) {
		sni_list = sni;
	} else {
		last = sni_list;
		while (last->next != NULL) {
			last = last->next;
		}
		last->next = sni;
	}

	return 0;
}

static void print_tls_error(int code, char *message, ...) {
	char cause[1024];
	va_list args;

	mbedtls_strerror(code, cause, 1023);
	cause[1023] = '\0';

	va_start(args, message);

	vfprintf(stderr, message, args);
	fprintf(stderr, ": %s (-0x%X)\n", cause, -code);

	va_end(args);
}

/* Load private key and certificate from file
 */
int tls_load_key_cert(char *file, mbedtls_pk_context **private_key, mbedtls_x509_crt **certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*private_key = (mbedtls_pk_context*)malloc(sizeof(mbedtls_pk_context))) == NULL) {
		return -1;
	}
	mbedtls_pk_init(*private_key);

	if ((result = mbedtls_pk_parse_keyfile(*private_key, file, NULL, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE)) != 0) {
		print_tls_error(result, "Error loading private key from %s", file);
		return -1;
	}

	if ((*certificate = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt))) == NULL) {
		return -1;
	}
	mbedtls_x509_crt_init(*certificate);

	if ((result = mbedtls_x509_crt_parse_file(*certificate, file)) != 0) {
		print_tls_error(result, "Error loading X.509 certificates from %s", file);
		return -1;
	}

	return 0;
}

/* Load CA certificate from file.
 */
int tls_load_ca_cert(char *file, mbedtls_x509_crt **ca_certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_certificate = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt))) == NULL) {
		return -1;
	}
	mbedtls_x509_crt_init(*ca_certificate);

	if ((result = mbedtls_x509_crt_parse_file(*ca_certificate, file)) != 0) {
		print_tls_error(result, "Error loading X.509 CA certificate from %s", file);
		return -1;
	}

	return 0;
}

/* Load CA CRL from file
 */
int tls_load_ca_crl(char *file, mbedtls_x509_crl **ca_crl) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_crl = (mbedtls_x509_crl*)malloc(sizeof(mbedtls_x509_crl))) == NULL) {
		return -1;
	}
	mbedtls_x509_crl_init(*ca_crl);

	if ((result = mbedtls_x509_crl_parse_file(*ca_crl, file)) != 0) {
		print_tls_error(result, "Error loading X.509 CA CRL from %s", file);
		return -1;
	}

	return 0;
}

/* Load CA root certificates
 */
int tls_load_ca_root_certs(char *source, mbedtls_x509_crt **ca_root_certs) {
	int result;
	char *error_msg = "Error loading root CA certificates from %s";

	if ((*ca_root_certs = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt))) == NULL) {
		return -1;
	}
	mbedtls_x509_crt_init(*ca_root_certs);

	if (file_type(source) == ft_dir) {
		if ((result = mbedtls_x509_crt_parse_path(*ca_root_certs, source)) != 0) {
			print_tls_error(result, error_msg, source);
			return -1;
		}
	} else {
		if ((result = mbedtls_x509_crt_parse_file(*ca_root_certs, source)) != 0) {
			print_tls_error(result, error_msg, source);
			return -1;
		}
	}

	return 0;
}

/* Accept incoming TLS connection
 */
int tls_accept(int *sock, mbedtls_ssl_context *context, mbedtls_ssl_config *config, int timeout) {
	int result, handshake;
	struct timeval timer;
	time_t start_time;

	mbedtls_ssl_init(context);

	if (mbedtls_ctr_drbg_reseed(&ctr_drbg, (const unsigned char*)"client thread", 13) != 0) {
		return -1;
	}

	if (mbedtls_ssl_setup(context, config) != 0) {
		return -1;
	}

	mbedtls_ssl_set_bio(context, sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	timer.tv_sec = timeout;
	timer.tv_usec = 0;
	setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	start_time = time(NULL);

	result = TLS_HANDSHAKE_OKE;
	while ((handshake = mbedtls_ssl_handshake(context)) != 0) {
		if (handshake == MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE) {
			mbedtls_ssl_free(context);
			result = TLS_HANDSHAKE_NO_MATCH;
			break;
		}

		if ((handshake != MBEDTLS_ERR_SSL_WANT_READ) && (handshake != MBEDTLS_ERR_SSL_WANT_WRITE)) {
			mbedtls_ssl_free(context);
			result = TLS_HANDSHAKE_ERROR;
			break;
		}

		if (time(NULL) - start_time >= timeout) {
			mbedtls_ssl_free(context);
			result = TLS_HANDSHAKE_TIMEOUT;
			break;
		}
	}

	if (result == TLS_HANDSHAKE_OKE) {
		timer.tv_sec = 0;
		timer.tv_usec = 0;
		setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	}

	return result;
}

/* See if data from TLS connection is read to be read
 */
int tls_pending(mbedtls_ssl_context *context) {
	return mbedtls_ssl_get_bytes_avail(context);
}

/* Read data from TLS connection
 */
int tls_receive(mbedtls_ssl_context *context, char *buffer, unsigned int maxlength) {
	int result;

	do {
		result = mbedtls_ssl_read(context, (unsigned char*)buffer, maxlength);
	} while (result == MBEDTLS_ERR_SSL_WANT_READ);

	if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
		return 0;
	} else if (result < 0) {
		return -1;
	}

	return result;
}

/* Send data via TLS connection
 */
int tls_send(mbedtls_ssl_context *context, const char *buffer, unsigned int length) {
	int result;

	do {
		result = mbedtls_ssl_write(context, (unsigned char*)buffer, length);
	} while (result == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (result < 0) {
		return -1;
	}

	return result;
}

/* Check if peer sent a client certificate
 */
bool tls_has_peer_cert(mbedtls_ssl_context *context) {
	return mbedtls_ssl_get_peer_cert(context) != NULL;
}

/* Get information from peer certificate
 */
int tls_get_peer_cert_info(mbedtls_ssl_context *context, char *subject_dn, char *issuer_dn, char *serial_nr, int length) {
	const mbedtls_x509_crt *peer_cert;

	if ((peer_cert = mbedtls_ssl_get_peer_cert(context)) == NULL) {
		return -1;
	}

	/* Subject DN
	 */
	if (mbedtls_x509_dn_gets(subject_dn, length, &(peer_cert->subject)) == -1) {
		return -1;
	}
	subject_dn[length - 1] = '\0';

	/* Issuer DN
	 */
	if (mbedtls_x509_dn_gets(issuer_dn, length, &(peer_cert->issuer)) == -1) {
		return -1;
	}
	issuer_dn[length - 1] = '\0';

	/* Serial number
	 */
	if (mbedtls_x509_serial_gets(serial_nr, length, &(peer_cert->serial)) == -1) {
		return -1;
	}
	serial_nr[length - 1] = '\0';

	return 0;
}

/* Get TLS version string
 */
char *tls_version_string(mbedtls_ssl_context *context) {
	return (char*)mbedtls_ssl_get_version(context);
}

/* Get TLS cipher
 */
char *tls_cipher_string(mbedtls_ssl_context *context) {
	return (char*)mbedtls_ssl_get_ciphersuite(context);
}

/* Close TLS connection
 */
void tls_close(mbedtls_ssl_context *context) {
	if (context != NULL) {
		mbedtls_ssl_close_notify(context);
		mbedtls_ssl_free(context);
	}
}

/* Connect to remote server via TLS
 */
int tls_connect(mbedtls_ssl_context *context, int *sock, char *hostname) {
	if (mbedtls_ctr_drbg_reseed(&ctr_drbg, (const unsigned char*)"Reverse Proxy", 13) != 0) {
		return -1;
	}

	mbedtls_ssl_init(context);

	if (mbedtls_ssl_setup(context, &client_config) != 0) {
		return -1;
	}

	mbedtls_ssl_set_bio(context, sock, mbedtls_net_send, mbedtls_net_recv, NULL);

	if (hostname != NULL) {
		mbedtls_ssl_set_hostname(context, hostname);
	}

	if (mbedtls_ssl_handshake(context) != 0) {
		mbedtls_ssl_free(context);
		return TLS_HANDSHAKE_ERROR;
	}

	return TLS_HANDSHAKE_OKE;
}

/* Send buffer via TLS
 */
int tls_send_buffer(mbedtls_ssl_context *context, const char *buffer, int size) {
	int bytes_written, total_written = 0;

	if (size <= 0) {
		return 0;
	} else while (total_written < size) {
		if ((bytes_written = mbedtls_ssl_write(context, (unsigned char*)buffer + total_written, size - total_written)) > 0) {
			total_written += bytes_written;
		} else if (bytes_written != MBEDTLS_ERR_SSL_WANT_WRITE) {
			return -1;
		}
	}

	return total_written;
}

#endif
