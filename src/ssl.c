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

#ifdef ENABLE_SSL

#define SSL_DEBUG_LEVEL          6
#define TIMESTAMP_SIZE          40
#define SNI_MAX_HOSTNAME_LEN   128
#define HS_TIMEOUT_CERT_SELECT  15

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/socket.h>
#include "alternative.h"
#include "ssl.h"
#include "libstr.h"
#include "log.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"
#include "polarssl/dhm.h"
#include "polarssl/ssl_cache.h"
#include "polarssl/error.h"

typedef struct type_sni_list {
	t_charlist *hostname;
	pk_context *private_key;
	x509_crt *certificate;
	x509_crt *ca_certificate;
	x509_crl *ca_crl;

	struct type_sni_list *next;
} t_sni_list;

static int ciphersuites[] = {
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
	0
};

static int ciphersuites_tls12[] = {
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
	0
};

static char *dhm_4096_P =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
	"FFFFFFFFFFFFFFFF";
static char *dhm_4096_G = "02";

/*
static char dhm_8192_P =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
	"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
	"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
	"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
	"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
	"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
	"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
	"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
	"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
	"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
	"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
	"12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
	"38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
	"741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
	"3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
	"22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
	"4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
	"062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
	"4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
	"B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
	"4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
	"9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
	"60C980DD98EDD3DFFFFFFFFFFFFFFFFF";
static char *dhm_8192_G = "02";
*/

static char *ssl_error_logfile;
static pthread_mutex_t random_mutex;
static pthread_mutex_t cache_mutex;
static ssl_cache_context cache;
static t_sni_list *sni_list = NULL;
static ctr_drbg_context ctr_drbg;
static entropy_context entropy;

/* Initialize SSL library
 */
int init_ssl_module(char *logfile) {
	ssl_error_logfile = logfile;

#if POLARSSL_VERSION_NUMBER >= 0x01030700
	if (version_check_feature("POLARSSL_THREADING_PTHREAD") != 0) {
		fprintf(stderr, "PolarSSL was compiled without the required POLARSSL_THREADING_PTHREAD compiler flag.\n");
		return -1;
	}
#endif

	entropy_init(&entropy);
	if (ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char*)"Hiawatha_RND", 10) != 0) {
		return -1;
	}
	ctr_drbg_set_prediction_resistance(&ctr_drbg, CTR_DRBG_PR_OFF);

	ssl_cache_init(&cache);
	ssl_cache_set_max_entries(&cache, 100);

	if (pthread_mutex_init(&random_mutex, NULL) != 0) {
		return -1;
	} else if (pthread_mutex_init(&cache_mutex, NULL) != 0) {
		return -1;
	}

	return 0;
}

/* Add SNI information to list
 */
int ssl_register_sni(t_charlist *hostname, pk_context *private_key, x509_crt *certificate,
                x509_crt *ca_certificate, x509_crl *ca_crl) {
	t_sni_list *sni;

	if ((sni = (t_sni_list*)malloc(sizeof(t_sni_list))) == NULL) {
		return -1;
	}

	sni->hostname = hostname;
	sni->private_key = private_key;
	sni->certificate = certificate;
	sni->ca_certificate = ca_certificate;
	sni->ca_crl = ca_crl;

	sni->next = sni_list;
	sni_list = sni;

	return 0;
}

/* SSL debug callback function
 */
#ifdef ENABLE_DEBUG
static void ssl_debug(void *thread_id, int level, const char *str) {
	if (level >= SSL_DEBUG_LEVEL) {
		return;
	}

	log_string(ssl_error_logfile, "PolarSSL (%d):%s", *(int*)thread_id, str);
}
#endif

/* Required to use random number generator functions in a multithreaded application
 */
static int ssl_random(void *p_rng, unsigned char *output, size_t len) {
	int result;

	pthread_mutex_lock(&random_mutex);
	result = ctr_drbg_random(p_rng, output, len);
	pthread_mutex_unlock(&random_mutex);

	return result;
}

static void print_ssl_error(char *message, int code) {
	char cause[1024];

	error_strerror(code, cause, 1023);
	cause[1023] = '\0';

	fprintf(stderr, "%s (-0x%X): %s\n", message, -code, cause);
}

/* Load private key and certificate from file
 */
int ssl_load_key_cert(char *file, pk_context **private_key, x509_crt **certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*private_key = (pk_context*)malloc(sizeof(pk_context))) == NULL) {
		return -1;
	}
	pk_init(*private_key);

	if ((result = pk_parse_keyfile(*private_key, file, NULL)) != 0) {
		print_ssl_error("Error loading RSA private key", result);
		return -1;
	}

	if ((*certificate = (x509_crt*)malloc(sizeof(x509_crt))) == NULL) {
		return -1;
	}
	x509_crt_init(*certificate);

	if ((result = x509_crt_parse_file(*certificate, file)) != 0) {
		print_ssl_error("Error loading X.509 certificates", result);
		return -1;
	}

	return 0;
}

/* Load CA certificate from file.
 */
int ssl_load_ca_cert(char *file, x509_crt **ca_certificate) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_certificate = (x509_crt*)malloc(sizeof(x509_crt))) == NULL) {
		return -1;
	}
	x509_crt_init(*ca_certificate);

	if ((result = x509_crt_parse_file(*ca_certificate, file)) != 0) {
		print_ssl_error("Error loading X.509 CA certificate", result);
		return -1;
	}

	return 0;
}

/* Load CA CRL from file
 */
int ssl_load_ca_crl(char *file, x509_crl **ca_crl) {
	int result;

	if (file == NULL) {
		return -1;
	}

	if ((*ca_crl = (x509_crl*)malloc(sizeof(x509_crl))) == NULL) {
		return -1;
	}
	x509_crl_init(*ca_crl);

	if ((result = x509_crl_parse_file(*ca_crl, file)) != 0) {
		print_ssl_error("Error loading X.509 CA CRL", result);
		return -1;
	}

	return 0;
}

/* Server Name Indication callback function
 */
static int sni_callback(void *sad, ssl_context *context, const unsigned char *sni_hostname, size_t len) {
	char hostname[SNI_MAX_HOSTNAME_LEN + 1];
	t_sni_list *sni;
	int i;

	if (len > SNI_MAX_HOSTNAME_LEN) {
		return -1;
	}

	memcpy(hostname, sni_hostname, len);
	hostname[len] = '\0';

	sni = sni_list;
	while (sni != NULL) {
		for (i = 0; i < sni->hostname->size; i++) {
			if (hostname_match(hostname, *(sni->hostname->item + i))) {
				((t_ssl_accept_data*)sad)->timeout = HS_TIMEOUT_CERT_SELECT;

				/* Set private key and certificate
				 */
				if ((sni->private_key != NULL) && (sni->certificate != NULL)) {
					ssl_set_own_cert(context, sni->certificate, sni->private_key);
				}

				/* Set CA certificate for SSL client authentication
				 */
				if (sni->ca_certificate != NULL) {
					ssl_set_authmode(context, SSL_VERIFY_REQUIRED);
					ssl_set_ca_chain(context, sni->ca_certificate, sni->ca_crl, NULL);
				}

				return 0;
			}
		}
		sni = sni->next;
	}

	return 0;
}

/* Accept incoming SSL connection
 */
int ssl_accept(t_ssl_accept_data *sad) {
	int result, handshake;
	struct timeval timer;
	time_t start_time;

	if (ssl_init(sad->context) != 0) {
		return -1;
	}

	ssl_set_endpoint(sad->context, SSL_IS_SERVER);
	if (sad->ca_certificate == NULL) {
		ssl_set_authmode(sad->context, SSL_VERIFY_NONE);
	} else {
		ssl_set_authmode(sad->context, SSL_VERIFY_REQUIRED);
		ssl_set_ca_chain(sad->context, sad->ca_certificate, sad->ca_crl, NULL);
		sad->timeout = HS_TIMEOUT_CERT_SELECT;
	}

	ssl_set_min_version(sad->context, SSL_MAJOR_VERSION_3, sad->min_ssl_version);
	ssl_set_renegotiation(sad->context, SSL_RENEGOTIATION_DISABLED);
	ssl_set_rng(sad->context, ssl_random, &ctr_drbg);
#ifdef ENABLE_DEBUG
	ssl_set_dbg(sad->context, ssl_debug, &(sad->thread_id));
#endif
	ssl_set_bio(sad->context, net_recv, sad->client_fd, net_send, sad->client_fd);
	ssl_set_sni(sad->context, sni_callback, sad);
	ssl_set_session_cache(sad->context, ssl_cache_get, &cache, ssl_cache_set, &cache);

	ssl_set_ciphersuites_for_version(sad->context, ciphersuites, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_0);
	ssl_set_ciphersuites_for_version(sad->context, ciphersuites, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1);
	ssl_set_ciphersuites_for_version(sad->context, ciphersuites, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_2);
	ssl_set_ciphersuites_for_version(sad->context, ciphersuites_tls12, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_3);

	ssl_set_own_cert(sad->context, sad->certificate, sad->private_key);
	if (sad->dh_size == 1024) {
		ssl_set_dh_param(sad->context, POLARSSL_DHM_RFC5114_MODP_1024_P, POLARSSL_DHM_RFC5114_MODP_1024_G);
	} else if (sad->dh_size == 2048) {
		ssl_set_dh_param(sad->context, POLARSSL_DHM_RFC5114_MODP_2048_P, POLARSSL_DHM_RFC5114_MODP_2048_G);
	} else if (sad->dh_size == 4096) {
		ssl_set_dh_param(sad->context, dhm_4096_P, dhm_4096_G);
	}

	timer.tv_sec = sad->timeout;
	timer.tv_usec = 0;
	setsockopt(*(sad->client_fd), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	start_time = time(NULL);

	result = SSL_HANDSHAKE_OKE;
	while ((handshake = ssl_handshake(sad->context)) != 0) {
		if (handshake == POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION) {
			result = SSL_HANDSHAKE_NO_MATCH;
			break;
		}

		if ((handshake != POLARSSL_ERR_NET_WANT_READ) && (handshake != POLARSSL_ERR_NET_WANT_WRITE)) {
			ssl_free(sad->context);
			sad->context = NULL;
			result = SSL_HANDSHAKE_ERROR;
			break;
		}

		if (time(NULL) - start_time >= sad->timeout) {
			ssl_free(sad->context);
			sad->context = NULL;
			result = SSL_HANDSHAKE_TIMEOUT;
			break;
		}
	}

	if (result == SSL_HANDSHAKE_OKE) {
		timer.tv_sec = 0;
		timer.tv_usec = 0;
		setsockopt(*(sad->client_fd), SOL_SOCKET, SO_RCVTIMEO, (void*)&timer, sizeof(struct timeval));
	}

	return result;
}

/* See if data from SSL connection is read to be read
 */
int ssl_pending(ssl_context *ssl) {
	return ssl_get_bytes_avail(ssl);
}

/* Read data from SSL connection
 */
int ssl_receive(ssl_context *ssl, char *buffer, unsigned int maxlength) {
	int result;

	do {
		result = ssl_read(ssl, (unsigned char*)buffer, maxlength);
	} while (result == POLARSSL_ERR_NET_WANT_READ);

	if (result < 0) {
		return -1;
	}

	return result;
}

/* Send data via SSL connection
 */
int ssl_send(ssl_context *ssl, const char *buffer, unsigned int length) {
	int result;

	do {
		result = ssl_write(ssl, (unsigned char*)buffer, length);
	} while (result == POLARSSL_ERR_NET_WANT_WRITE);

	if (result < 0) {
		return -1;
	}

	return result;
}

/* Check if peer sent a client certificate
 */
bool ssl_has_peer_cert(ssl_context *context) {
	return ssl_get_peer_cert(context) != NULL;
}

/* Get information from peer certificate
 */
int get_peer_cert_info(ssl_context *context, char *subject_dn, char *issuer_dn, char *serial_nr, int length) {
	const x509_crt *peer_cert;

	if ((peer_cert = ssl_get_peer_cert(context)) == NULL) {
		return -1;
	}

	/* Subject DN
	 */
	if (x509_dn_gets(subject_dn, length, &(peer_cert->subject)) == -1) {
		return -1;
	}
	subject_dn[length - 1] = '\0';

	/* Issuer DN
	 */
	if (x509_dn_gets(issuer_dn, length, &(peer_cert->issuer)) == -1) {
		return -1;
	}
	issuer_dn[length - 1] = '\0';

	/* Serial number
	 */
	if (x509_serial_gets(serial_nr, length, &(peer_cert->serial)) == -1) {
		return -1;
	}
	serial_nr[length - 1] = '\0';

	return 0;
}

/* Get SSL version string
 */
char *ssl_version_string(ssl_context *context) {
	return (char*)ssl_get_version(context);
}

/* Get SSL cipher
 */
char *ssl_cipher_string(ssl_context *context) {
	return (char*)ssl_get_ciphersuite(context);
}

/* Close SSL connection
 */
void ssl_close(ssl_context *ssl) {
	if (ssl != NULL) {
		ssl_close_notify(ssl);
		ssl_free(ssl);
	}
}

/* Clean up SSL library
 */
void ssl_shutdown(void) {
	ssl_cache_free(&cache);
}

#ifdef ENABLE_RPROXY
int ssl_connect(ssl_context *ssl, int *sock, char *hostname) {
#ifdef ENABLE_DEBUG
	int no_thread_id = 0;
#endif

	memset(ssl, 0, sizeof(ssl_context));
	if (ssl_init(ssl) != 0) {
		return -1;
	}

	ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	ssl_set_authmode(ssl, SSL_VERIFY_NONE);

	ssl_set_rng(ssl, ssl_random, &ctr_drbg);
#ifdef ENABLE_DEBUG
	ssl_set_dbg(ssl, ssl_debug, &no_thread_id);
#endif
	ssl_set_bio(ssl, net_recv, sock, net_send, sock);

	if (hostname != NULL) {
		ssl_set_hostname(ssl, hostname);
	}
	ssl_set_ciphersuites(ssl, ciphersuites);

	if (ssl_handshake(ssl) != 0) {
		return SSL_HANDSHAKE_ERROR;
	}

	return SSL_HANDSHAKE_OKE;
}

int ssl_send_completely(ssl_context *ssl, const char *buffer, int size) {
	int bytes_written, total_written = 0;

	if (size <= 0) {
		return 0;
	} else while (total_written < size) {
		if ((bytes_written = ssl_write(ssl, (unsigned char*)buffer + total_written, size - total_written)) > 0) {
			total_written += bytes_written;
		} else if (bytes_written != POLARSSL_ERR_NET_WANT_WRITE) {
			return -1;
		}
	}

	return total_written;
}
#endif

#endif
