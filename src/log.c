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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "global.h"
#include "liblist.h"
#include "libfs.h"
#include "libstr.h"
#include "log.h"
#include "memdbg.h"

#define BUFFER_SIZE        2 * KILOBYTE
#define TIMESTAMP_SIZE    40
#define LOGFILE_OPEN_TIME 30
#define GZIP_BUFFER_SIZE   8 * KILOBYTE
#define IP_ADDRESS_SIZE MAX_IP_STR_LEN + 1

#ifdef CYGWIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

static pthread_mutex_t accesslog_mutex;
static int day_of_year;

/* Initialize log module
 */
int init_log_module(void) {
	time_t now;
	struct tm s;

	if (pthread_mutex_init(&accesslog_mutex, NULL) != 0) {
		return -1;
	}

	now = time(NULL);
	localtime_r(&now, &s);
	day_of_year = s.tm_yday;

	return 0;
}

/* Write a timestamp to a logfile.
 */
static void print_timestamp(char *str) {
	time_t t;
	struct tm s;

	time(&t);
	localtime_r(&t, &s);
	str[TIMESTAMP_SIZE - 1] = '\0';
	strftime(str, TIMESTAMP_SIZE - 1, "%a %d %b %Y %T %z|", &s);
}

/* Keep escape characters out of the logfile
 */
static char *secure_string(char *str) {
	char *c = str;

	if (str != NULL) {
		while (*c != '\0') {
			if (*c == '\27') {
				*c = ' ';
			}
			c++;
		}
	}

	return str;
}

/*---< Main log functions >------------------------------------------*/

/* Log the Hiawatha process ID.
 */
void log_pid(t_config *config, pid_t pid, uid_t UNUSED(server_uid)) {
	FILE *fp;

	if ((fp = fopen(config->pidfile, "w")) == NULL) {
		fprintf(stderr, "Warning: can't write PID file %s.\n", config->pidfile);
		return;
	}

	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);

#ifndef CYGWIN
	if (chmod(config->pidfile, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		fprintf(stderr, "Warning: can't chmod PID file %s. Make sure it's only writable for root!\n", config->pidfile);
	}
	if (server_uid == 0) {
		if (chown(config->pidfile, 0, 0) == -1) {
			fprintf(stderr, "Warning: can't chown PID file %s. Make sure it's owned by root!\n", config->pidfile);
		}
	}
#endif
}

/* Log a text.
 */
void log_string(char *logfile, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE];

	if ((logfile == NULL) || (mesg == NULL)) {
		return;
	} else if ((fp = fopen(logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	print_timestamp(str);
	fprintf(fp, "%s", str);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log a system message.
 */
void log_system(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE + 2];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(session->config->system_logfile, "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s", str);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log an error for a specific file
 */
void log_file_error(t_session *session, char *file, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE + 2];

	if (mesg == NULL) {
		return;
	}

	if (session->host == NULL) {
		if (session->config->first_host->error_logfile == NULL) {
			return;
		}
		fp = fopen(session->config->first_host->error_logfile, "a");
	} else {
		if (session->host->error_logfile == NULL) {
			return;
		}
		fp = fopen(session->host->error_logfile, "a");
	}
	if (fp == NULL) {
		return;
	}

	va_start(args, mesg);

	if (session->config->anonymize_ip) {
		anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	} else {
		ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	}

	strcat(str, "|");
	print_timestamp(str + strlen(str));
	if (file == NULL) {
		fprintf(fp, "%s", str);
	} else {
		fprintf(fp, "%s%s|", str, file);
	}
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}

/* Log an error
 */
void log_error(t_session *session, char *mesg) {
	log_file_error(session, session->file_on_disk, mesg);
}

/* Log a HTTP request.
 */
void log_request(t_session *session) {
	char str[BUFFER_SIZE + 1], timestamp[TIMESTAMP_SIZE], ip_address[IP_ADDRESS_SIZE];
	char *user, *field, *uri, *vars, *path_info;
	t_http_header *http_header;
	int offset;
	time_t t;
	struct tm s;

	if (session->host->access_logfile == NULL) {
		return;
	} else if (ip_allowed(&(session->ip_address), session->config->logfile_mask) == deny) {
		return;
	}

	str[BUFFER_SIZE] = '\0';

#ifdef ENABLE_TOOLKIT
	if (session->request_uri == NULL) {
#endif
		uri = secure_string(session->uri);
		path_info = secure_string(session->path_info);
		vars = secure_string(session->vars);
#ifdef ENABLE_TOOLKIT
	} else {
		uri = secure_string(session->request_uri);
		path_info = NULL;
		vars = NULL;
	}
#endif

	if ((user = session->remote_user) != NULL) {
		user = secure_string(user);
	}

	if (session->config->log_format == hiawatha) {
		/* Hiawatha log format
		 */
		if (session->config->anonymize_ip) {
			anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
		} else {
			ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
		}

		strcat(str, "|");
		offset = strlen(str);
		print_timestamp(str + offset);
		offset += strlen(str + offset);

		if (user == NULL) {
			user = "";
		}

		snprintf(str + offset, BUFFER_SIZE - offset, "%d|%lld|%s|%s %s", session->return_code, (long long)session->bytes_sent, user, secure_string(session->method), uri);
		offset += strlen(str + offset);

		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s", secure_string(session->http_version));
			offset += strlen(str + offset);
		}

		if (offset < BUFFER_SIZE) {
			http_header = session->http_headers;
			while (http_header != NULL) {
				if ((strncasecmp("Cookie:", http_header->data, 7) != 0) && (strncasecmp("Authorization:", http_header->data, 14) != 0) && (strncasecmp("Proxy-Authorization:", http_header->data, 20) != 0)) {
					snprintf(str + offset, BUFFER_SIZE - offset, "|%s", secure_string(http_header->data));
					if ((offset += strlen(str + offset)) >= BUFFER_SIZE) {
						break;
					}
				}
				http_header = http_header->next;
			}
		}
	} else {
		/* Common Log Format
		 */
		if (session->config->anonymize_ip) {
			anonymized_ip_to_str(&(session->ip_address), ip_address, IP_ADDRESS_SIZE);
		} else {
			ip_to_str(&(session->ip_address), ip_address, IP_ADDRESS_SIZE);
		}

		if (user == NULL) {
			user = "-";
		}

		time(&t);
		localtime_r(&t, &s);
		timestamp[TIMESTAMP_SIZE - 1] = '\0';
		strftime(timestamp, TIMESTAMP_SIZE - 1, "%d/%b/%Y:%T %z", &s);

		snprintf(str, BUFFER_SIZE, "%s - %s [%s] \"%s %s", ip_address, user, timestamp, secure_string(session->method), uri);
		offset = strlen(str);
		if ((offset < BUFFER_SIZE) && (path_info != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "/%s", path_info);
			offset += strlen(str + offset);
		}
		if ((offset < BUFFER_SIZE) && (vars != NULL)) {
			snprintf(str + offset, BUFFER_SIZE - offset, "?%s", vars);
			offset += strlen(str + offset);
		}
		if (offset < BUFFER_SIZE) {
			snprintf(str + offset, BUFFER_SIZE - offset, " %s\" %d %lld", secure_string(session->http_version), session->return_code, (long long)session->bytes_sent);
		}

		if (session->config->log_format == extended) {
			/* Extended Common Log Format
			 */
			offset += strlen(str + offset);
			if (offset < BUFFER_SIZE) {
				if ((field = get_http_header("Referer:", session->http_headers)) != NULL) {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", secure_string(field));
				} else {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"-\"");
				}
				offset += strlen(str + offset);
			}
			if (offset < BUFFER_SIZE) {
				if ((field = get_http_header("User-Agent:", session->http_headers)) != NULL) {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"%s\"", secure_string(field));
				} else {
					snprintf(str + offset, BUFFER_SIZE - offset, " \"-\"");
				}
			}
		}
	}

	pthread_mutex_lock(&accesslog_mutex);

	if (*(session->host->access_fp) == NULL) {
		*(session->host->access_fp) = fopen(session->host->access_logfile, "a");
	}

	if (*(session->host->access_fp) != NULL) {
		fprintf(*(session->host->access_fp), "%s"EOL, str);
		fflush(*(session->host->access_fp));
	}

	pthread_mutex_unlock(&accesslog_mutex);
}

/* Log garbage sent by a client.
 */
void log_garbage(t_session *session) {
	int i, spaces = 2;
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if ((session->config->garbage_logfile == NULL) || (session->request == NULL)) {
		return;
	}

	for (i = 0; i < session->bytes_in_buffer; i++) {
		if (session->request[i] == '\0') {
			if (spaces > 0) {
				session->request[i] = ' ';
				spaces--;
			} else {
				session->request[i] = '\r';
			}
		}
	}

	if ((fp = fopen(session->config->garbage_logfile, "a")) == NULL) {
		return;
	}

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%s"EOL, str, session->request);
	fclose(fp);
}

/* Log exploit attempt
 */
void log_exploit_attempt(t_session *session, char *type, char *data) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE], *host, *uri, *unknown = "<unknown>";

	if ((session->config->exploit_logfile == NULL) || (type == NULL)) {
		return;
	} else if ((fp = fopen(session->config->exploit_logfile, "a")) == NULL) {
		return;
	}

	host = (session->host->hostname.size > 0) ? session->host->hostname.item[0] : unknown;
	uri = (session->request_uri != NULL) ? session->request_uri : unknown;

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	if (data == NULL) {
		fprintf(fp, "%s%s|%s|%s"EOL, str, host, uri, type);
	} else {
		fprintf(fp, "%s%s|%s|%s|%s"EOL, str, host, uri, type, data);
	}
	fclose(fp);
}

/* Log an unbanning.
 */
void log_unban(char *logfile, t_ip_addr *ip_address, unsigned long connect_attempts) {
	FILE *fp;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if ((logfile == NULL) || (ip_address == NULL)) {
		return;
	} else if ((fp = fopen(logfile, "a")) == NULL) {
		return;
	}

	ip_to_str(ip_address, str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%sUnbanned (%lu connect attempts during ban)"EOL, str, connect_attempts);
	fclose(fp);
}

/* Log a CGI error.
 */
void log_cgi_error(t_session *session, char *mesg) {
	FILE *fp;
	char *c, str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];
	int len = 0;

	if ((session->host->error_logfile == NULL) || (mesg == NULL)) {
		return;
	}

	c = mesg;
	while (*c != '\0') {
		if (*c == '\n') {
			if (*(c + 1) == '\0') {
				*c = '\0';
			} else {
				*c = '|';
			}
		} else {
			len++;
		}
		c++;
	}

	if (len == 0) {
		return;
	}

	if ((fp = fopen(session->host->error_logfile, "a")) == NULL) {
		return;
	}

	if (session->config->anonymize_ip) {
		anonymized_ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	} else {
		ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	}

	strcat(str, "|");
	print_timestamp(str + strlen(str));
	if (session->file_on_disk == NULL) {
		fprintf(fp, "%s-|%s"EOL, str, secure_string(mesg));
	} else {
		fprintf(fp, "%s%s|%s"EOL, str, session->file_on_disk, secure_string(mesg));
	}
	fclose(fp);
}

/* Close open access logfiles.
 */
void close_logfiles(t_host *host, time_t now) {
	pthread_mutex_lock(&accesslog_mutex);

	while (host != NULL) {
		if ((now >= host->access_time + LOGFILE_OPEN_TIME) || (now == 0)) {
			if (*(host->access_fp) != NULL) {
				fclose(*(host->access_fp));
				*(host->access_fp) = NULL;
			}
		}
		host = host->next;
	}

	pthread_mutex_unlock(&accesslog_mutex);
}

/* Close all open logfile descriptors
 */
void close_logfiles_for_cgi_run(t_host *host) {
	while (host != NULL) {
		if (*(host->access_fp) != NULL) {
			fclose(*(host->access_fp));
		}
		host = host->next;
	}
}

/* Compress logfile
 */
static int gzip_logfile(char *file) {
	char *gz_file = NULL, buffer[GZIP_BUFFER_SIZE];
	int result = -1, fd_in = -1, fd_out = -1;
	int bytes_read, bytes_written, total_written;
	struct stat stat_in;
	gzFile gzhandle = NULL;

	/* Input file
	 */
	if ((fd_in = open(file, O_RDONLY)) == -1) {
		goto gzip_fail;
	}

	if (fstat(fd_in, &stat_in) == -1) {
		goto gzip_fail;
	}

	/* Output file
	 */
	if ((gz_file = (char*)malloc(strlen(file) + 4)) == NULL) {
		goto gzip_fail;
	}
	sprintf(gz_file, "%s.gz", file);

	if ((fd_out = open(gz_file, O_CREAT | O_WRONLY, stat_in.st_mode)) == -1) {
		goto gzip_fail;
	}

	if ((gzhandle = gzdopen(fd_out, "w6")) == NULL) {
		goto gzip_fail;
	}

	/* Compress file
	 */
	while ((bytes_read = read(fd_in, buffer, GZIP_BUFFER_SIZE)) != 0) {
		if (bytes_read == -1) {
			if (errno != EAGAIN) {
				goto gzip_fail;
			}
			continue;
		}

		total_written = 0;
		while (total_written < bytes_read) {
			if ((bytes_written = gzwrite(gzhandle, buffer + total_written, bytes_read - total_written)) == -1) {
				goto gzip_fail;
			}
			total_written += bytes_written;
		}
	}

	result = 0;

gzip_fail:
	if (gzhandle != NULL) {
		gzclose(gzhandle);
	}

	if (fd_out != -1) {
		close(fd_out);
		if (result == -1) {
			unlink(gz_file);
		}
	}

	if (fd_in != -1) {
		close(fd_in);
	}

	if (result == 0) {
		if (unlink(file) == -1) {
			unlink(gz_file);
		}
	}

	if (gz_file != NULL) {
		free(gz_file);
	}

	return result;
}

/* Rotate logfile
 */
static int rotate_access_logfile(t_host *host, char *timestamp) {
	int fd;
	char *logfile, *dot;
	size_t len;

	if ((logfile = (char*)malloc(strlen(host->access_logfile) + strlen(timestamp) + 2)) == NULL) {
		return -1;
	}

	if ((dot = strrchr(host->access_logfile, '.')) != NULL) {
		len = dot - host->access_logfile;
		memcpy(logfile, host->access_logfile, len);
		logfile[len] = '\0';
		strcat(logfile, "-");
		strcat(logfile, timestamp);
		strcat(logfile, dot);
	} else {
		strcpy(logfile, host->access_logfile);
		strcat(logfile, "-");
		strcat(logfile, timestamp);
	}

	if (rename(host->access_logfile, logfile) == -1) {
		free(logfile);
		return -1;
	}

	if ((fd = open(host->access_logfile, O_CREAT, LOG_PERM)) == -1) {
		rename(logfile, host->access_logfile);
		free(logfile);
		return -1;
	}
	close(fd);

	gzip_logfile(logfile);

	free(logfile);

	return 0;
}

/* Rotate logfiles
 */
void rotate_access_logfiles(t_config *config, time_t now) {
	struct tm s;
	char timestamp[16];
	t_host *host;
	int result;

	localtime_r(&now, &s);
	if (s.tm_yday == day_of_year) {
		return;
	}
	day_of_year = s.tm_yday;

	strftime(timestamp, 15, "%Y-%m-%d", &s);

	host = config->first_host;
	while (host != NULL) {
		if (host->access_logfile == NULL) {
			result = 0;
		} else if (host->rotate_access_log == daily) {
			result = rotate_access_logfile(host, timestamp);
		} else if ((host->rotate_access_log == weekly) && (s.tm_wday == 1)) {
			result = rotate_access_logfile(host, timestamp);
		} else if ((host->rotate_access_log == monthly) && (s.tm_mday == 1)) {
			result = rotate_access_logfile(host, timestamp);
		} else {
			result = 0;
		}

		if (result == -1) {
			log_string(config->system_logfile, "Error rotating %s", host->access_logfile);
		}

		host = host->next;
	}
}

#ifdef ENABLE_DEBUG
/* Log debug information
 */
void log_debug(t_session *session, char *mesg, ...) {
	FILE *fp;
	va_list args;
	char str[TIMESTAMP_SIZE + IP_ADDRESS_SIZE];

	if (mesg == NULL) {
		return;
	} else if ((fp = fopen(LOG_DIR"/access.log", "a")) == NULL) {
		return;
	}

	va_start(args, mesg);

	ip_to_str(&(session->ip_address), str, IP_ADDRESS_SIZE);
	strcat(str, "|");
	print_timestamp(str + strlen(str));
	fprintf(fp, "%s%05d|", str, session->thread_id);
	vfprintf(fp, mesg, args);
	fprintf(fp, EOL);
	fclose(fp);

	va_end(args);
}
#endif
