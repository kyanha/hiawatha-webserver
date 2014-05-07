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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "global.h"
#include "alternative.h"
#include "libstr.h"
#include "libfs.h"
#include "target.h"
#include "http.h"
#include "httpauth.h"
#include "log.h"
#include "cgi.h"
#include "send.h"
#ifdef ENABLE_CACHE
#include "cache.h"
#endif
#ifdef ENABLE_MONITOR
#include "monitor.h"
#endif
#ifdef ENABLE_TOMAHAWK
#include "tomahawk.h"
#endif
#ifdef ENABLE_XSLT
#include "xslt.h"
#endif

#define MAX_VOLATILE_SIZE      1 * MEGABYTE
#define FILE_BUFFER_SIZE      32 * KILOBYTE
#define MAX_OUTPUT_HEADER     16 * KILOBYTE
#define CGI_BUFFER_SIZE       32 * KILOBYTE
#define RPROXY_BUFFER_SIZE    32 * KILOBYTE
#define MAX_TRACE_HEADER       2 * KILOBYTE
#define VALUE_SIZE            64
#define WAIT_FOR_LOCK          3

#define rs_QUIT       -1
#define rs_DISCONNECT -2
#define rs_FORCE_QUIT -3

#define NEW_FILE -1

char *hs_chunked = "Transfer-Encoding: chunked\r\n";  /* 28 */
char *fb_alterlist   = "access denied via alterlist";

extern char *fb_filesystem;
extern char *fb_symlink;
extern char *hs_eol;
extern char *hs_conn;
extern char *hs_concl;
extern char *hs_conlen;
extern char *hs_contyp;
extern char *hs_forwarded;

/* Read a file from disk and send it to the client.
 */
int send_file(t_session *session) {
	char *buffer = NULL, value[VALUE_SIZE + 1], *pos, *date, *range, *range_begin, *range_end;
	long bytes_read, total_bytes, size, speed;
	off_t file_size, send_begin, send_end, send_size;
	int  retval, handle = -1;
	struct stat status;
	struct tm fdate;
#ifdef ENABLE_CACHE
	t_cached_object *cached_object;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "send file";
#endif
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_FILE);
#endif
	session->mimetype = get_mimetype(session->extension, session->config->mimetype);

	/* gzip content encoding
	 */
	if (session->host->use_gz_file) {
		if ((pos = get_http_header("Accept-Encoding:", session->http_headers)) != NULL) {
			if ((strstr(pos, "gzip")) != NULL) {
				size = strlen(session->file_on_disk);
				memcpy(session->file_on_disk + size, ".gz\0", 4);
				if ((handle = open(session->file_on_disk, O_RDONLY)) != -1) {
					session->encode_gzip = true;
				} else {
					*(session->file_on_disk + size) = '\0';
				}
			}
		}
	}

	/* Open the file for reading
	 */
	if (handle == -1) {
		if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
			if (errno == EACCES) {
				log_error(session, fb_filesystem);
				return 403;
			}
			return 404;
		}
	}

	/* File hashes
	 */
	if (session->host->file_hashes != NULL) {
		if (file_hash_match(session->file_on_disk, session->host->file_hashes) == false) {
			log_file_error(session, session->file_on_disk, "invalid file hash");
#ifdef ENABLE_MONITOR
			if (session->config->monitor_enabled) {
				monitor_count_exploit(session);
				monitor_event("Invalid file hash for %s", session->file_on_disk);
			}
#endif
			return 403;
		}
	}

	/* Symlink check
	 */
	if (session->host->follow_symlinks == false) {
		switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
			case error:
				close(handle);
				log_error(session, "error while scanning file for symlinks");
				return 500;
			case not_found:
				close(handle);
				return 404;
			case no_access:
			case yes:
				close(handle);
				log_error(session, fb_symlink);
				return 403;
			case no:
				break;
		}
	}

	/* Modified-Since
	 */
	if (session->handling_error == false) {
		if ((date = get_http_header("If-Modified-Since:", session->http_headers)) != NULL) {
			if (if_modified_since(handle, date) == 0) {
				close(handle);
				return 304;
			}
		} else if ((date = get_http_header("If-Unmodified-Since:", session->http_headers)) != NULL) {
			if (if_modified_since(handle, date) == 1) {
				close(handle);
				return 412;
			}
		}
	}

	/* Set throttlespeed
	 */
	pos = session->uri + session->uri_len;
	while ((*pos != '.') && (pos != session->uri)) {
		pos--;
	}
	if (*pos == '.') {
		if ((speed = get_throttlespeed(pos, session->config->throttle)) != 0) {
			if ((session->throttle == 0) || (speed < session->throttle)) {
				session->throttle = speed;
			}
		}
		if ((speed = get_throttlespeed(session->mimetype, session->config->throttle)) != 0) {
			if ((session->throttle == 0) || (speed < session->throttle)) {
				session->throttle = speed;
			}
		}
	}

	if ((file_size = filesize(session->file_on_disk)) == -1) {
		close(handle);
		log_error(session, "error while determining filesize");
		return 500;
	}
	send_begin = 0;
	send_end = file_size - 1;
	send_size = file_size;

	/* Range
	 */
	if (session->handling_error == false) {
		if ((range = get_http_header("Range:", session->http_headers)) != NULL) {
			/* Check for multi-range
			 */
			if (strchr(range, ',') != NULL) {
				close(handle);
				return 416;
			}

			if (strncmp(range, "bytes=", 6) == 0) {
				if ((range = strdup(range + 6)) == NULL) {
					close(handle);
					return 500;
				}

				if (split_string(range, &range_begin, &range_end, '-') == 0) {

					if (*range_begin != '\0') {
						if ((send_begin = str2int(range_begin)) >= 0) {
							if (*range_end != '\0') {
								if ((send_end = str2int(range_end)) >= 0) {
									/* bytes=XX-XX */
									session->return_code = 206;
								}
							} else {
								/* bytes=XX- */
								session->return_code = 206;
							}
						}
					} else {
						if ((send_begin = str2int(range_end)) >= 0) {
							/* bytes=-XX */
							send_begin = file_size - send_begin - 1;
							session->return_code = 206;
						}
					}

					if (session->return_code == 206) {
						if (send_begin >= file_size) {
							close(handle);
							free(range);
							return 416;
						}
						if (send_begin < 0) {
							send_begin = 0;
						}
						if (send_end >= file_size) {
							send_end = file_size - 1;
						}
						if (send_begin <= send_end) {
							send_size = send_end - send_begin + 1;
						} else {
							close(handle);
							free(range);
							return 416;
						}
					}

					/* Change filepointer offset
					 */
					if (send_begin > 0) {
						if (lseek(handle, send_begin, SEEK_SET) == -1) {
							session->return_code = 200;
						}
					}

					if (session->return_code == 200) {
						send_begin = 0;
						send_end = file_size - 1;
						send_size = file_size;
					}
				}
				free(range);
			}
		}
	}

	retval = -1;
	if (send_header(session) == -1) {
		goto fail;
	}
	if (session->return_code == 401) {
		if (session->host->auth_method == basic) {
			if (send_basic_auth(session) == -1) {
				goto fail;
			}
		} else {
			if (send_digest_auth(session) == -1) {
				goto fail;
			}
		}
	}

	value[VALUE_SIZE] = '\0';

	/* Last-Modified
	 */
	if (fstat(handle, &status) == -1) {
		goto fail;
	} else if (gmtime_r(&(status.st_mtime), &fdate) == NULL) {
		goto fail;
	} else if (send_buffer(session, "Last-Modified: ", 15) == -1) {
		goto fail;
	} else if (strftime(value, VALUE_SIZE, "%a, %d %b %Y %X GMT\r\n", &fdate) == 0) {
		goto fail;
	} else if (send_buffer(session, value, strlen(value)) == -1) {
		goto fail;
	}

	/* Content-Range
	 */
	if (session->return_code == 206) {
		if (send_buffer(session, "Content-Range: bytes ", 21) == -1) {
			goto fail;
		} else if (snprintf(value, VALUE_SIZE, "%lld-%lld/%lld\r\n", (long long)send_begin, (long long)send_end, (long long)file_size) == -1) {
			goto fail;
		} else if (send_buffer(session, value, strlen(value)) == -1) {
			goto fail;
		}
	}

	if (send_buffer(session, hs_conlen, 16) == -1) {
		goto fail;
	} else if (snprintf(value, VALUE_SIZE, "%lld\r\n\r\n", (long long)send_size) == -1) {
		goto fail;
	} else if (send_buffer(session, value, strlen(value)) == -1) {
		goto fail;
	}
	session->header_sent = true;

	if ((session->request_method != HEAD) && (send_size > 0)) {
		if (is_volatile_object(session) && (file_size <= MAX_VOLATILE_SIZE)) {
			/* volatile object
			 */
			if ((buffer = (char*)malloc(send_size)) == NULL) {
				goto fail;
			}

			total_bytes = 0;
			do {
				if ((bytes_read = read(handle, buffer + total_bytes, send_size - total_bytes)) == -1) {
					if (errno == EINTR) {
						bytes_read = 0;
					}
				} else {
					total_bytes += bytes_read;
				}
			} while ((bytes_read != -1) && (total_bytes < send_size));

			if (bytes_read == -1) {
				goto fail;
			} else if (send_buffer(session, buffer, send_size) == -1) {
				goto fail;
			}

			memset(buffer, 0, send_size);
		} else {
			/* Normal file
			 */
#ifdef ENABLE_CACHE
#ifdef ENABLE_MONITOR
			if (session->host->monitor_host) {
				cached_object = NULL;
			} else
#endif
				if ((cached_object = search_cache_for_file(session, session->file_on_disk)) == NULL) {
					cached_object = add_file_to_cache(session, session->file_on_disk);
				}

			if (cached_object != NULL) {
				if (send_begin + send_size > cached_object->content_length) {
					done_with_cached_object(cached_object, true);
					cached_object = NULL;
				}
			}

			if (cached_object != NULL) {
				if (send_buffer(session, cached_object->content + send_begin, send_size) == -1) {
					goto fail;
				}
				done_with_cached_object(cached_object, false);
			} else
#endif
			if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) == NULL) {
				goto fail;
			} else {
				do {
					switch ((bytes_read = read(handle, buffer, FILE_BUFFER_SIZE))) {
						case -1:
							if (errno != EINTR) {
								goto fail;
							}
							break;
						case 0:
							send_size = 0;
							break;
						default:
							if (bytes_read > send_size) {
								bytes_read = send_size;
							}
							if (send_buffer(session, buffer, bytes_read) == -1) {
								goto fail;
							}
							send_size -= bytes_read;
					}
				} while (send_size > 0);

				memset(buffer, 0, FILE_BUFFER_SIZE);
			}
		}

	}
	
	retval = 200;

fail:
	if (buffer != NULL) {
		free(buffer);
	}

	close(handle);

	return retval;
}

static int extract_http_code(char *data) {
	int result = -1;
	char *code, c;

	if (strncmp(data, "HTTP/", 5) == 0) {
		data += 5;
		while ((*data != '\0') && (*data != ' ')) {
			data++;
		}
	}

	while (*data == ' ') {
		data++;
	}
	code = data;

	while (*data != '\0') {
		if ((*data == '\r') || (*data == ' ')) {
			c = *data;
			*data = '\0';
			result = str2int(code);
			*data = c;
			break;
		}
		data++;
	}

	return result;
}

/* Run a CGI program and send output to the client.
 */
int execute_cgi(t_session *session) {
	int retval = 200, result, handle, len, header_length;
	char *end_of_header, *str_begin, *str_end, *code, c, *str;
	bool in_body = false, send_in_chunks = true, wrap_cgi, check_file_exists;
	t_cgi_result cgi_result;
	t_connect_to *connect_to;
	t_cgi_info cgi_info;
	pid_t cgi_pid = -1;
#ifdef CYGWIN
	char *old_path, *win32_path;
#endif
#ifdef ENABLE_CACHE
	t_cached_object *cached_object;
	char *cache_buffer = NULL;
	int  cache_size = 0, cache_time = 0;
#endif
#ifdef ENABLE_MONITOR
	bool timed_out = false, measure_runtime = false;
	struct timeval tv_begin, tv_end;
	struct timezone tz_begin, tz_end;
	int runtime, diff;
	char *event_key, *event_value, *event_end;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "execute CGI";
#endif
#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_CGI);
#endif

	if (session->cgi_type != fastcgi) {
		wrap_cgi = (session->host->wrap_cgi != NULL) ||
			((session->local_user != NULL) && session->config->wrap_user_cgi);
	} else {
		wrap_cgi = false;
	}

	/* HTTP/1.0 does not support chunked Transfer-Encoding.
	 */
	if (*(session->http_version + 7) == '0') {
		session->keep_alive = false;
	}

	if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
		check_file_exists = true;
	} else if ((session->cgi_type == fastcgi) && (session->fcgi_server != NULL)) {
		check_file_exists = false;
	} else {
		check_file_exists = false;
	}

	if (check_file_exists) {
		if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
			if (errno == EACCES) {
				log_error(session, fb_filesystem);
				return 403;
			}
			return 404;
		} else {
			close(handle);
		}

		/* File hashes
		 */
		if (session->host->file_hashes != NULL) {
			if (file_hash_match(session->file_on_disk, session->host->file_hashes) == false) {
				log_file_error(session, session->file_on_disk, "invalid file hash");
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					monitor_count_exploit(session);
					monitor_event("Invalid file hash for %s", session->file_on_disk);
				}
#endif
				return 403;
			}
		}
	}

	if (session->host->execute_cgi == false) {
		log_error(session, "CGI execution not allowed");
		return 403;
	}

#ifdef CYGWIN
	if ((session->config->platform == windows) && (session->cgi_type == binary)) {
		chmod(session->file_on_disk, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}
#endif

	if ((wrap_cgi == false) && (session->cgi_type != fastcgi)) {
		if (session->cgi_type == binary) {
			switch (can_execute(session->file_on_disk, session->config->server_uid, session->config->server_gid, &(session->config->groups))) {
				case error:
					log_error(session, "error during CGI preprocess");
					return 500;
				case not_found:
					return 404;
				case no_access:
				case no:
					log_error(session, fb_filesystem);
					return 403;
				case yes:
					break;
			}
		}

		if (session->host->follow_symlinks == false) {
			switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
				case error:
					log_error(session, "error while searching for symlinks in CGI path");
					return 500;
				case not_found:
					return 404;
				case no_access:
				case yes:
					log_error(session, fb_symlink);
					return 403;
				case no:
					break;
			}
		}
	}

	/* Prevent Cross-site Scripting
	 */
	if (session->host->prevent_xss) {
		prevent_xss(session);
	}

	/* Prevent Cross-site Request Forgery
	 */
	if (session->host->prevent_csrf) {
		prevent_csrf(session);
	}

	/* Prevent SQL injection
	 */
	if (session->host->prevent_sqli) {
		result = prevent_sqli(session);
		if (result == 1) {
			session->error_cause = ec_SQL_INJECTION;
		}
		if (result != 0) {
			return -1;
		}
	}

#ifdef ENABLE_CACHE
	/* Search for CGI output in cache
	 */
	if (session->request_method == GET) {
		if ((cached_object = search_cache_for_cgi_output(session)) != NULL) {
			if (send_header(session) == -1) {
				retval = rs_DISCONNECT;
			} else if (send_buffer(session, cached_object->header, cached_object->header_length) == -1) {
				retval = rs_DISCONNECT;
			} else if (send_buffer(session, cached_object->content, cached_object->content_length) == -1) {
				retval = rs_DISCONNECT;
			}

			done_with_cached_object(cached_object, false);

			return retval;
		}
	}
#endif

	cgi_info.type = session->cgi_type;
	cgi_info.input_buffer_size = cgi_info.error_buffer_size = CGI_BUFFER_SIZE;
	cgi_info.input_len = cgi_info.error_len = 0;

#ifdef CYGWIN
	if ((session->config->platform == windows) && ((session->cgi_type == fastcgi) || (session->cgi_type == script))) {
		if ((old_path = strdup(session->file_on_disk)) == NULL) {
			return -1;
		}
		if ((win32_path = strdup(cygwin_to_windows(old_path))) == NULL) {
			free(old_path);
			return -1;
		}
		free(session->file_on_disk);
		session->file_on_disk = win32_path;
		free(old_path);
	}
#endif

#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled) {
		measure_runtime = gettimeofday(&tv_begin, &tz_begin) == 0;
	}
#endif

	if (session->cgi_type == fastcgi) {
		cgi_info.read_header = true;
		if ((connect_to = select_connect_to(session->fcgi_server, &(session->ip_address))) == NULL) {
			return 503;
		} else if ((cgi_info.from_cgi = connect_to_fcgi_server(connect_to)) == -1) {
			connect_to->available = false;
			log_string(session->config->system_logfile, "can't connect to FastCGI server %s", session->fcgi_server->fcgi_id);
			return 503;
		} else {
			connect_to->available = true;
			if (send_fcgi_request(session, cgi_info.from_cgi) == -1) {
				log_error(session, "error while sending data to FastCGI server");
				return 500;
			}
		}
	} else {
		cgi_info.wrap_cgi = wrap_cgi;
		if ((cgi_pid = fork_cgi_process(session, &cgi_info)) == -1) {
			log_error(session, "error while forking CGI process");
			return 500;
		}
	}

	if ((cgi_info.input_buffer = (char*)malloc(cgi_info.input_buffer_size + 1)) == NULL) {
		retval = -1;
	} else if ((cgi_info.error_buffer = (char*)malloc(cgi_info.error_buffer_size + 1)) == NULL) {
		free(cgi_info.input_buffer);
		retval = -1;
	}

	if (retval != 200) {
		if (session->cgi_type == fastcgi) {
			close(cgi_info.from_cgi);
		} else {
			close(cgi_info.to_cgi);
			close(cgi_info.from_cgi);
			close(cgi_info.cgi_error);
		}
		return retval;
	}

	cgi_info.deadline = session->time + session->host->time_for_cgi;

	do {
		if (time(NULL) > cgi_info.deadline) {
			cgi_result = cgi_TIMEOUT;
		} else if (session->cgi_type == fastcgi) {
			cgi_result = read_from_fcgi_server(session, &cgi_info);
		} else {
			cgi_result = read_from_cgi_process(session, &cgi_info);
		}

		switch (cgi_result) {
			case cgi_ERROR:
				log_error(session, "error while executing CGI");
				retval = 500;
				break;
			case cgi_TIMEOUT:
				log_error(session, "CGI application timeout");
				if (in_body) {
					retval = rs_DISCONNECT;
				} else {
					retval = 500;
				}
				if (session->config->kill_timedout_cgi && (session->cgi_type != fastcgi)) {
					if (kill(cgi_pid, SIGTERM) != -1) {
						sleep(1);
						kill(cgi_pid, SIGKILL);
					}
				}
#ifdef ENABLE_MONITOR
				if (session->config->monitor_enabled) {
					timed_out = true;
				}
#endif
				break;
			case cgi_FORCE_QUIT:
				retval = rs_FORCE_QUIT;
				break;
			case cgi_OKE:
				if (cgi_info.error_len > 0) {
					/* Error received from CGI
					 */
					*(cgi_info.error_buffer + cgi_info.error_len) = '\0';
					log_cgi_error(session, cgi_info.error_buffer);
					cgi_info.error_len = 0;
				}

				if (cgi_info.input_len > 0) {
					/* Data received from CGI
					 */
					if (in_body) {
						/* Read content
						 */
						if (session->request_method != HEAD) {
							if (send_in_chunks) {
								result = send_chunk(session, cgi_info.input_buffer, cgi_info.input_len);
							} else {
								result = send_buffer(session, cgi_info.input_buffer, cgi_info.input_len);
							}
							if (result == -1) {
								retval = rs_DISCONNECT;
							}
						}

#ifdef ENABLE_CACHE
						/* Add body content to cache buffer
						 */
						if ((cache_buffer != NULL) && (retval == 200)) {
							if ((off_t)(cache_size + cgi_info.input_len) > session->config->cache_max_filesize) {
								free(cache_buffer);
								cache_buffer = NULL;
							} else {
								memcpy(cache_buffer + cache_size, cgi_info.input_buffer, cgi_info.input_len);
								cache_size += cgi_info.input_len;
								*(cache_buffer + cache_size) = '\0';
							}
						}
#endif
						cgi_info.input_len = 0;
					} else {
						/* Read HTTP header
						 */
						*(cgi_info.input_buffer + cgi_info.input_len) = '\0';

						if ((end_of_header = strstr(cgi_info.input_buffer, "\r\n\r\n")) == NULL) {
							/* Fix crappy CGI headers
							 */
							if ((result = fix_crappy_cgi_headers(&cgi_info)) == -1) {
								retval = 500;
								break;
							} else if (result == 0) {
								end_of_header = strstr(cgi_info.input_buffer, "\r\n\r\n");
							}
						}

						if (end_of_header != NULL) {
							header_length = end_of_header + 4 - cgi_info.input_buffer;

							if (session->throttle == 0) {
								if ((str_begin = strncasestr(cgi_info.input_buffer, hs_contyp, header_length)) != NULL) {
									if ((str_end = strchr(str_begin, '\r')) != NULL) {
										str_begin += 14;
										c = *str_end;
										*str_end = '\0';
										session->throttle = get_throttlespeed(str_begin, session->config->throttle);
										*str_end = c;
									}
								}
							}

							if ((str = find_cgi_header(cgi_info.input_buffer, header_length, hs_conn)) != NULL) {
								if (strncmp(str + 12, hs_concl, 7) == 0) {
									session->keep_alive = false;
								}

							}

#ifdef ENABLE_MONITOR
							/* Log X-Hiawatha-Monitor header
							 */
							str = cgi_info.input_buffer;
							len = header_length;
							while ((event_key = find_cgi_header(str, len, "X-Hiawatha-Monitor:")) != NULL) {
								event_value = event_key + 19;
								while (*event_value == ' ') {
									event_value++;
								}

								if ((event_end = strstr(event_value, "\r\n")) == NULL) {
									break;
								}

								if (session->config->monitor_enabled) {
									*event_end = '\0';
									monitor_event("%s", event_value);
									*event_end = '\r';
								}

								event_end += 2;
								memmove(event_key, event_end, cgi_info.input_len - (event_end - cgi_info.input_buffer));

								diff = event_end - event_key;
								header_length -= diff;
								end_of_header -= diff;
								cgi_info.input_len -= diff;

								len = header_length - (str - cgi_info.input_buffer);
							}
#endif

							if (session->expires > -1) {
								if (find_cgi_header(cgi_info.input_buffer, header_length, "Expires:") != NULL) {
									session->expires = -1;
								}
							}

#ifdef ENABLE_CACHE
							/* Look for store-in-cache CGI header
							 */
							if (session->request_method == GET) {
								if ((cache_time = cgi_cache_time(cgi_info.input_buffer, header_length)) > 0) {
									if ((cache_buffer = (char*)malloc(session->config->cache_max_filesize + 1)) != NULL) {
										*(cache_buffer + session->config->cache_max_filesize) = '\0';
									}
								}
							}

							/* Look for remove-from-cache CGI header
							 */
							handle_remove_header_for_cgi_cache(session, cgi_info.input_buffer, header_length);
#endif

							if (find_cgi_header(cgi_info.input_buffer, header_length, "Location:") != NULL) {
								session->return_code = 302;
							} else if ((code = strncasestr(cgi_info.input_buffer, "Status:", header_length)) != NULL) {
								result = extract_http_code(code + 7);

								if ((result <= 0) || (result > 999)) {
									log_error(session, "invalid status code received from CGI");
								} else if (result != 200) {
									session->return_code = result;
									if (result == 500) {
										log_error(session, "CGI returned 500 Internal Error");
									}
									if (session->host->trigger_on_cgi_status) {
										retval = result;
										break;
									}

#ifdef ENABLE_CACHE
									if (cache_buffer != NULL) {
										clear_free(cache_buffer, cache_size);
										cache_buffer = NULL;
									}
#endif
								}
							}

							if (send_header(session) == -1) {
								retval = rs_DISCONNECT;
								break;
							}

							if ((strncasestr(cgi_info.input_buffer, hs_conlen, header_length) != NULL) || (session->keep_alive == false)) {
								send_in_chunks = false;
							} else if (send_buffer(session, hs_chunked, 28) == -1) {
								retval = rs_DISCONNECT;
								break;
							}

							/* Send the header.
							 */
							end_of_header += 4;
							len = end_of_header - cgi_info.input_buffer;
							if (send_buffer(session, cgi_info.input_buffer, len) == -1) {
								retval = rs_DISCONNECT;
								break;
							}
							if (send_buffer(session, NULL, 0) == -1) {
								retval = rs_DISCONNECT;
								break;
							}
							session->header_sent = true;

							/* Send first part of the body
							 */
							if (session->request_method != HEAD) {
								if ((len = cgi_info.input_len - len) > 0) {
									if (send_in_chunks) {
										result = send_chunk(session, end_of_header, len);
									} else {
										result = send_buffer(session, end_of_header, len);
									}
									if (result == -1) {
										retval = rs_DISCONNECT;
										break;
									}
								}
							}

#ifdef ENABLE_CACHE
							/* Add header to cache buffer
							 */
							if (cache_buffer != NULL) {
								if ((off_t)(cache_size + cgi_info.input_len) > session->config->cache_max_filesize) {
									clear_free(cache_buffer, cache_size);
									cache_buffer = NULL;
								} else {
									memcpy(cache_buffer + cache_size, cgi_info.input_buffer, cgi_info.input_len);
									cache_size += cgi_info.input_len;
									*(cache_buffer + cache_size) = '\0';
								}
							}
#endif

							in_body = true;
							cgi_info.input_len = 0;
						} else if (cgi_info.input_len > MAX_OUTPUT_HEADER) {
							log_error(session, "CGI's HTTP header too large");
							retval = 500;
							break;
						}
					}
				}
				break;
			case cgi_END_OF_DATA:
				if (in_body) {
					retval = rs_QUIT;
					if (send_in_chunks && (session->request_method != HEAD)) {
						if (send_chunk(session, NULL, 0) == -1) {
							retval = rs_DISCONNECT;
						}
					}
				} else {
					retval = 500;
					if (cgi_info.input_len == 0) {
						log_error(session, "no output");
					} else {
						log_error(session, "CGI only printed a HTTP header, no content");
					}
				}
		} /* switch */
	} while (retval == 200);

#ifdef ENABLE_MONITOR
	if (session->config->monitor_enabled && measure_runtime) {
		if (gettimeofday(&tv_end, &tz_end) == 0) {
			runtime = tv_end.tv_sec - tv_begin.tv_sec;
			if (tv_end.tv_usec < tv_begin.tv_usec) {
				runtime--;
			}
			monitor_count_cgi(session, runtime, timed_out);
		}
	}
#endif

	session->time = time(NULL);

#ifdef ENABLE_CACHE
	/* Add cache buffer to cache
	 */
	if (cache_buffer != NULL) {
		if (retval == rs_QUIT) {
			add_cgi_output_to_cache(session, cache_buffer, cache_size, cache_time);
		}
		clear_free(cache_buffer, cache_size);
	}
#endif

	if (session->cgi_type == fastcgi) {
		close(cgi_info.from_cgi);
	} else {
		close(cgi_info.to_cgi);
		if (cgi_info.from_cgi != -1) {
			close(cgi_info.from_cgi);
		}
		if (cgi_info.cgi_error != -1) {
			close(cgi_info.cgi_error);
		}
	}

	if (session->config->wait_for_cgi && (cgi_pid != -1)) {
		waitpid(cgi_pid, NULL, 0);
	}

	switch (retval) {
		case rs_DISCONNECT:
		case rs_FORCE_QUIT:
			session->keep_alive = false;
		case rs_QUIT:
			retval = 200;
	}

	clear_free(cgi_info.input_buffer, cgi_info.input_len);
	clear_free(cgi_info.error_buffer, cgi_info.error_len);

	return retval;
}

/* Handle TRACE requests
 */
int handle_trace_request(t_session *session) {
	int code, body_size;
	size_t len;
	char buffer[MAX_TRACE_HEADER + 1];
	t_http_header *header;

#ifdef ENABLE_DEBUG
	session->current_task = "handle TRACE";
#endif

	body_size = 3;
	body_size += strlen(session->method) + session->uri_len;
	if (session->vars != NULL) {
		body_size += 1 + strlen(session->vars);
	}
	body_size += strlen(session->http_version);

	header = session->http_headers;
	while (header != NULL) {
		body_size += header->length + 1;
		header = header->next;
	}

	buffer[MAX_TRACE_HEADER] = '\0';

	/* Header
	 */
	if (snprintf(buffer, MAX_TRACE_HEADER, "%d\r\nContent-Type: message/http\r\n\r\n", body_size) < 0) {
		return 500;
	} else if (send_header(session) == -1) {
		return -1;
	} else if (send_buffer(session, hs_conlen, 16) == -1) {
		return -1;
	} else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
		return -1;
	}
	session->header_sent = true;

	/* Body
	 */
	if ((code = snprintf(buffer, MAX_TRACE_HEADER, "%s %s", session->method, session->uri)) < 0) {
		return -1;
	} else if (code >= MAX_TRACE_HEADER) {
		return -1;
	} else if (session->vars != NULL) {
		len = strlen(buffer);
		if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, "?%s", session->vars)) < 0) {
			return -1;
		} else if (code >= MAX_TRACE_HEADER) {
			return -1;
		}
	}
	len = strlen(buffer);
	if ((code = snprintf(buffer + len, MAX_TRACE_HEADER - len, " %s\r\n", session->http_version)) < 0) {
		return -1;
	} else if (send_buffer(session, buffer, strlen(buffer)) == -1) {
		return -1;
	}

	header = session->http_headers;
	while (header != NULL) {
		if (send_buffer(session, header->data, header->length) == -1) {
			return -1;
		} else if (send_buffer(session, "\n", 1) == -1) {
			return -1;
		}
		header = header->next;
	}

	return 200;
}

/* Determine allowance of alter requests
 */
static t_access allow_alter(t_session *session) {
	char *x_forwarded_for;
	t_ip_addr forwarded_ip;
	t_access access;

	if ((access = ip_allowed(&(session->ip_address), session->host->alter_list)) != allow) {
		return access;
	} else if ((x_forwarded_for = get_http_header(hs_forwarded, session->http_headers)) == NULL) {
		return allow;
	} else if (parse_ip(x_forwarded_for, &forwarded_ip) == -1) {
		return allow;
	} else if (ip_allowed(&forwarded_ip, session->host->alter_list) == deny) {
		return deny;
	}

	return unspecified;
}

/* Handle PUT requests
 */
int handle_put_request(t_session *session) {
	int auth_result, handle_write, handle_read = -1, result = -1, total_written = 0, lock_timeout;
	off_t write_begin, write_end, total_size, file_size;
	ssize_t bytes_read;
	char *range, *value, *rest, *buffer;
	bool range_found;
	struct flock file_lock;

#ifdef ENABLE_DEBUG
	session->current_task = "handle PUT";
#endif

	if (session->uploaded_file == NULL) {
		return 500;
	}

	/* Access check
	 */
	switch (allow_alter(session)) {
		case deny:
		case unspecified:
			log_error(session, fb_alterlist);
			return 403;
		case allow:
			break;
		case pwd:
			if ((auth_result = http_authentication_result(session, false)) != 200) {
				return auth_result;
			}
			if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
				return 403;
			}
			break;
	}

	if (session->uri_is_dir) {
		return 405;
	}

	range = get_http_header("Content-Range:", session->http_headers);
	range_found = (range != NULL);

	/* Open file for writing
	 */
	if ((handle_write = open(session->file_on_disk, O_WRONLY)) == -1) {
		/* New file */
		if (range_found) {
			return 416;
		}
		if ((handle_write = open(session->file_on_disk, O_CREAT|O_WRONLY, session->host->alter_fmode)) == -1) {
			log_error(session, fb_filesystem);
			return 403;
		}
		file_size = NEW_FILE;
		result = 201;
	} else {
		/* Existing file */
		if ((file_size = filesize(session->file_on_disk)) == -1) {
			close(handle_write);
			return 500;
		}
		result = 204;
	}

	/* Lock file for writing
	 */
	file_lock.l_type = F_WRLCK;
	file_lock.l_whence = SEEK_SET;
	file_lock.l_start = 0;
	file_lock.l_len = 0;
	file_lock.l_pid = 0;
	lock_timeout = WAIT_FOR_LOCK;

	while (fcntl(handle_write, F_SETLK, &file_lock) == -1) {
		if (errno == EINTR) {
			continue;
		} else if ((lock_timeout > 0) && ((errno == EACCES) || (errno == EAGAIN))) {
			lock_timeout--;
			sleep(1);
		} else {
			log_error(session, "can't lock file for writing (PUT)");
			close(handle_write);
			if (file_size == NEW_FILE) {
				unlink(session->file_on_disk);
			}
			return 500;
		}
	}

	file_lock.l_type = F_UNLCK;

	/* Handle upload range
	 */
	if (range_found) {
		if (strncmp(range, "bytes ", 6) != 0) {
			result = 416;
		} else {
			if ((range = strdup(range + 6)) == NULL) {
				result = -1;
			} else if (split_string(range, &value, &rest, '-') == -1) {
				result = 416;
			} else if (strlen(value) > 9) {
				result = 416;
			} else if ((write_begin = str2int(value)) == -1) {
				result = 416;
			} else if (split_string(rest, &value, &rest, '/') == -1) {
				result = 416;
			} else if ((write_end = str2int(value)) == -1) {
				result = 416;
			} else if ((total_size = str2int(rest)) == -1) {
				result = 416;
			} else if (total_size != file_size) {
				result = 416;
			} else if (write_begin > write_end) {
				result = 416;
			} else if (write_begin > file_size) {
				result = 416;
			} else if (session->uploaded_size != (write_end - write_begin + 1)) {
				result = 416;
			} else if (write_begin > 0) {
				if (lseek(handle_write, write_begin, SEEK_SET) == -1) {
					result = 500;
				}
			}

			free(range);
		}
	}

	/* Open temporary file for reading
	 */
	if ((result == 201) || (result == 204)) {
		if ((handle_read = open(session->uploaded_file, O_RDONLY)) == -1) {
			fcntl(handle_write, F_SETLK, &file_lock);
			close(handle_write);
			if (file_size == NEW_FILE) {
				unlink(session->file_on_disk);
			}
			return 500;
		}

		if ((file_size != NEW_FILE) && (range_found == false)) {
			if (ftruncate(handle_write, session->uploaded_size) == -1) {
				result = 500;
			}
		}

		/* Write content
		 */
		if (result != 500) {
			if ((buffer = (char*)malloc(FILE_BUFFER_SIZE)) != NULL) {
				while (total_written < session->uploaded_size) {
					if ((bytes_read = read(handle_read, buffer, FILE_BUFFER_SIZE)) != -1) {
						if (bytes_read == 0) {
							break;
						} else if (write_buffer(handle_write, buffer, bytes_read) != -1) {
							total_written += bytes_read;
						} else {
							result = 500;
							break;
						}
					} else if (errno != EINTR) {
						result = 500;
						break;
					}
				}
				free(buffer);
			} else {
				result = 500;
			}
		}
	}

	/* Finish upload
	 */
	if (handle_read != -1) {
		close(handle_read);
	}
	fcntl(handle_write, F_SETLK, &file_lock);
	fsync(handle_write);
	close(handle_write);
	if ((result != 201) && (result != 204) && (file_size == NEW_FILE)) {
		unlink(session->file_on_disk);
	}

	return result;
}

/* Handle DELETE requests
 */
int handle_delete_request(t_session *session) {
	int auth_result;

#ifdef ENABLE_DEBUG
	session->current_task = "handle DELETE";
#endif

	/* Access check
	 */
	switch (allow_alter(session)) {
		case deny:
		case unspecified:
			log_error(session, fb_alterlist);
			return 403;
		case allow:
			break;
		case pwd:
			if ((auth_result = http_authentication_result(session, false)) != 200) {
				return auth_result;
			}
			if (group_oke(session, session->remote_user, &(session->host->alter_group)) == false) {
				return 403;
			}
			break;
	}

	/* Don't delete directories
	 */
	if (session->uri_is_dir) {
		return 405;
	}

	/* Delete file
	 */
	if (unlink(session->file_on_disk) == -1) {
		switch (errno) {
			case EACCES:
				log_error(session, fb_filesystem);
				return 403;
			case ENOENT:
				return 404;
			case EISDIR:
			case ENOTDIR:
				return 405;
			default:
				return 500;
		}
	}

	return 204;
}

#ifdef ENABLE_XSLT
int handle_xml_file(t_session *session, char *xslt_file) {
	int handle;

#ifdef ENABLE_DEBUG
	session->current_task = "handle XML";
#endif

	if ((handle = open(session->file_on_disk, O_RDONLY)) == -1) {
		if (errno == EACCES) {
			log_error(session, fb_filesystem);
			return 403;
		}
		return 404;
	} else {
		close(handle);
	}

	/* Symlink check
	 */
	if (session->host->follow_symlinks == false) {
		switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
			case error:
				log_error(session, "error while scanning file for symlinks");
				return 500;
			case not_found:
				return 404;
			case no_access:
			case yes:
				log_error(session, fb_symlink);
				return 403;
			case no:
				break;
		}
	}

	return transform_xml(session, xslt_file);
}
#endif

#ifdef ENABLE_RPROXY
static int remove_header(char *buffer, char *header, int header_length, int size) {
	char *pos;
	size_t len;

	if ((pos = strncasestr(buffer, header, header_length)) == NULL) {
		return 0;
	}

	len = strlen(header);
	while (*(pos + len) != '\n') {
		if (*(pos + len) == '\0') {
			return 0;
		}
		len++;
	}
	len++;

	memmove(pos, pos + len, size - len - (pos - buffer));

	return len;
}

static int find_chunk_size(char *buffer, int size, int *chunk_size, int *chunk_left) {
	int extra, total;
	char *c;

	if (*chunk_left > 0) {
		if (*chunk_left >= size) {
			*chunk_left -= size;
			return 0;
		}
		buffer += *chunk_left;
		size -= *chunk_left;
		*chunk_left = 0;
	}

	if ((c = strstr(buffer, "\r\n")) == NULL) {
		return -1;
	} else if (c - buffer > 10) {
		return -1;
	}

	*chunk_size = 0;
	extra = 4;
	c = buffer;
	while (*c != '\r') {
		*chunk_size = (16 * (*chunk_size)) + (int)hex_to_int(*c);
		extra++;
		c++;
	}

	if (*chunk_size == 0) { 
		return 0;
	}

	total = *chunk_size + extra;

	if (total < size) {
		return find_chunk_size(buffer + total, size - total, chunk_size, chunk_left);
	}

	if (total > size) {
		*chunk_left = total - size;
	}

	return 0;
}

int proxy_request(t_session *session, t_rproxy *rproxy) {
	t_rproxy_options options;
	t_rproxy_webserver webserver;
	t_rproxy_result rproxy_result;
	char buffer[RPROXY_BUFFER_SIZE + 1], *end_of_header, *str, *eol;
	int bytes_read, bytes_in_buffer = 0, result = 200, code, poll_result, send_result, delta;
	int content_length = -1, content_read = 0, chunk_size = 0, chunk_left = 0, header_length;
	bool header_read = false, keep_reading = true, keep_alive, chunked_transfer = false, send_in_chunks = false;
	struct pollfd poll_data;
	time_t deadline;
#ifdef ENABLE_CACHE
	t_cached_object *cached_object;
	char *cache_buffer = NULL;
	int  cache_size = 0, cache_time = 0;
#endif

#ifdef ENABLE_DEBUG
	session->current_task = "proxy request";
#endif

#ifdef ENABLE_CACHE
	/* Search for CGI output in cache
	 */
	if (session->request_method == GET) {
		if ((cached_object = search_cache_for_rproxy_output(session)) != NULL) {
			if (session->keep_alive) {
				if (send_buffer(session, cached_object->header, cached_object->header_length) == -1) {
					result = rs_DISCONNECT;
				}
			} else {
				if (send_buffer(session, cached_object->header, cached_object->header_length - 2) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, hs_conn, 12) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, hs_concl, 7) == -1) {
					result = rs_DISCONNECT;
				} else if (send_buffer(session, "\r\n", 2) == -1) {
					result = rs_DISCONNECT;
				}
			}
			
			if (send_buffer(session, cached_object->content, cached_object->content_length) == -1) {
				result = rs_DISCONNECT;
			}

			done_with_cached_object(cached_object, false);

			return result;
		}
	}
#endif

	keep_alive = session->keep_alive && rproxy->keep_alive;

	/* Intialize data structure
	 */
	options.client_socket = session->client_socket;
	options.client_ip = &(session->ip_address);
	options.port = session->binding->port;
	options.method = session->method;
	options.uri = session->request_uri;
	options.hostname = session->hostname;
	options.http_headers = session->http_headers;
	options.body = session->body;
	options.content_length = session->content_length;
	options.remote_user = session->remote_user;
#ifdef ENABLE_SSL
	options.use_ssl = session->binding->use_ssl;
#endif
#ifdef ENABLE_CACHE
	options.cache_extensions = &(session->config->cache_rproxy_extensions);
#endif

	init_rproxy_result(&rproxy_result);

	if (session->rproxy_kept_alive && ((same_ip(&(session->rproxy_addr), &(rproxy->ip_addr)) == false) || (session->rproxy_port != rproxy->port))) {
#ifdef ENABLE_SSL
		if (session->rproxy_use_ssl) {
			ssl_close(&(session->rproxy_ssl));
		}
#endif
		close(session->rproxy_socket);
		session->rproxy_kept_alive = false;
	}

	/* Test if kept-alive connection is still alive
	 */
	if (session->rproxy_kept_alive) {
		if (recv(session->rproxy_socket, buffer, 1, MSG_DONTWAIT | MSG_PEEK) == -1) {
			if (errno != EAGAIN) {
#ifdef ENABLE_SSL
				if (session->rproxy_use_ssl) {
					ssl_close(&(session->rproxy_ssl));
				}
#endif
				close(session->rproxy_socket);

				session->rproxy_kept_alive = false;
			}
		}
	}

	if (session->rproxy_kept_alive) {
		/* Use kept alive connection
		 */
		webserver.socket = session->rproxy_socket;
#ifdef ENABLE_SSL
		webserver.use_ssl = session->rproxy_use_ssl;
		if (webserver.use_ssl) {
			memcpy(&(webserver.ssl), &(session->rproxy_ssl), sizeof(ssl_context));
		}
#endif
	} else {
		/* Connect to webserver
		 */
		if ((webserver.socket = connect_to_server(&(rproxy->ip_addr), rproxy->port)) == -1) {
			return 503;
		}

#ifdef ENABLE_SSL
		webserver.use_ssl = rproxy->use_ssl;
		if (webserver.use_ssl) {
			if (ssl_connect(&(webserver.ssl), &(webserver.socket), rproxy->hostname) == SSL_HANDSHAKE_ERROR) {
				close(webserver.socket);
				return 503;
			}
		}
#endif
	}

	/* Send request to webserver
	 */
	if (send_request_to_webserver(&webserver, &options, rproxy, &rproxy_result, session->keep_alive) == -1) {
		result = -1;
	}
	session->bytes_sent += rproxy_result.bytes_sent;

	/* Read result from webserver and send to client
	 */
	deadline = time(NULL) + rproxy->timeout;

	do {
#ifdef ENABLE_SSL
		poll_result = session->binding->use_ssl ? ssl_pending(&(session->ssl_context)) : 0;

		if (poll_result == 0) {
#endif
			poll_data.fd = webserver.socket;
			poll_data.events = POLL_EVENT_BITS;
			poll_result = poll(&poll_data, 1, 1000);
#ifdef ENABLE_SSL
		}
#endif

		switch (poll_result) {
			case -1:
				if (errno != EINTR) {
					result = -1;
					keep_reading = false;
					keep_alive = false;
				}
				break;
			case 0:
				if (time(NULL) > deadline) {
					result = 504;
					keep_reading = false;
					keep_alive = false;
				}
				break;
			default:
				if (RPROXY_BUFFER_SIZE - bytes_in_buffer > 0) {
#ifdef ENABLE_SSL
					if (webserver.use_ssl) {
						bytes_read = ssl_receive(&(webserver.ssl), buffer + bytes_in_buffer, RPROXY_BUFFER_SIZE - bytes_in_buffer);
					} else
#endif
						bytes_read = read(webserver.socket, buffer + bytes_in_buffer, RPROXY_BUFFER_SIZE - bytes_in_buffer);
				} else {
					bytes_read = -1;
				}

				switch (bytes_read) {
					case -1:
						if (errno != EINTR) {
							result = -1;
							keep_reading = false;
							keep_alive = false;
						}
						break;
					case 0:
						keep_reading = false;
						break;
					default:
						/* Read first line and extract return code
						 */
						bytes_in_buffer += bytes_read;
						*(buffer + bytes_in_buffer) = '\0';

						if (header_read == false) {
							/* Look for header
							 */
							if ((end_of_header = strstr(buffer, "\r\n\r\n")) != NULL) {
								header_length = end_of_header + 4 - buffer;

								if (strncmp(buffer, "HTTP/1.0 ", 9) == 0) {
									buffer[7] = '1';
								}

								if ((code = extract_http_code(buffer)) != -1) {
									session->return_code = code;
								}

								if ((code != 200) && (session->host->trigger_on_cgi_status)) {
									result = code;
									keep_reading = false;
									keep_alive = false;
									break;
								}

#ifdef ENABLE_CACHE
								if ((code == 200) && (session->request_method == GET)) {
									if ((cache_time = rproxy_cache_time(session, buffer, header_length)) > 0) {
										if ((cache_buffer = (char*)malloc(session->config->cache_max_filesize + 1)) != NULL) {
											*(cache_buffer + session->config->cache_max_filesize) = '\0';
										}
									}
								}

								handle_remove_header_for_rproxy_cache(session, buffer, header_length);
#endif

								/* Check for close-connection
								 */
								if (session->keep_alive) {
									if ((str = strncasestr(buffer, hs_conn, header_length)) != NULL) {
										str += 12;
										if (strncmp(str, "close\r\n", 7) == 0) {
											keep_alive = false;
										}
									}
								}

								delta = remove_header(buffer, hs_conn, header_length, bytes_in_buffer);
								bytes_in_buffer -= delta;
								end_of_header -= delta;
								header_length -= delta;
								bytes_read -= delta;

								if ((session->request_method == HEAD) || empty_body_because_of_http_status(code)) {
									content_length = 0;
								} else if (keep_alive) {
									/* Parse content length
									 */
									if ((str = strncasestr(buffer, hs_conlen, header_length)) != NULL) {
										str += 16;
										if ((eol = strchr(str, '\r')) != NULL) {
											*eol = '\0';
											content_length = str2int(str);
											*eol = '\r';
										}
									}

									/* Determine if is chunked transfer encoding
									 */
									if (strncasestr(buffer, hs_chunked, header_length) != NULL) {
										chunked_transfer = true;
										content_length = -1;
										chunk_size = header_length;
										chunk_left = chunk_size;
									}
								} else if (session->keep_alive &&
								          (strncasestr(buffer, hs_conlen, header_length) == NULL) &&
									      (strncasestr(buffer, hs_chunked, header_length) == NULL)) {
									/* We need to forward result in chunks
									 */
									if (send_buffer(session, buffer, header_length - 2) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, hs_chunked, 28) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, "\r\n", 2) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									} else if (send_buffer(session, NULL, 0) == -1) {
										result = -1;
										keep_reading = false;
										keep_alive = false;
										break;
									}

#ifdef ENABLE_CACHE
									/* Add output to cache buffer
									 */
									if (cache_buffer != NULL) {
										if ((off_t)(cache_size + header_length) > session->config->cache_max_filesize) {
											clear_free(cache_buffer, cache_size);
											cache_buffer = NULL;
										} else {
											memcpy(cache_buffer + cache_size, buffer, header_length);
											cache_size += header_length;
											*(cache_buffer + cache_size) = '\0';
										}
									}
#endif

									if ((content_read = bytes_in_buffer - header_length) > 0) {
										memmove(buffer, end_of_header + 4, content_read);
									}
									bytes_in_buffer = content_read;
									send_in_chunks = true;
								}

								if (send_in_chunks == false) {
									content_read = bytes_in_buffer - header_length;
								}

								header_read = true;

								if (bytes_in_buffer == 0) {
									continue;
								}
							} else if (bytes_in_buffer == RPROXY_BUFFER_SIZE) {
								result = -1;
								keep_reading = false;
								keep_alive = false;
								break;
							} else {
								continue;
							}
						} else {
							/* Dealing with body
							 */
							content_read += bytes_read;
						}

						if (content_read == content_length) {
							keep_reading = false;
						}

						/* Send buffer content
						 */
						if (send_in_chunks) {
							send_result = send_chunk(session, buffer, bytes_in_buffer);
						} else {
							send_result = send_buffer(session, buffer, bytes_in_buffer);
						}

						if (send_result == -1) {
							result = -1;
							keep_reading = false;
							keep_alive = false;
							break;
						}

#ifdef ENABLE_CACHE
						/* Add output to cache buffer
						 */
						if (cache_buffer != NULL) {
							if ((off_t)(cache_size + bytes_in_buffer) > session->config->cache_max_filesize) {
								clear_free(cache_buffer, cache_size);
								cache_buffer = NULL;
							} else {
								memcpy(cache_buffer + cache_size, buffer, bytes_in_buffer);
								cache_size += bytes_in_buffer;
								*(cache_buffer + cache_size) = '\0';
							}
						}
#endif

						if (chunked_transfer) {
							if (find_chunk_size(buffer, bytes_in_buffer, &chunk_size, &chunk_left) == -1) {
								keep_reading = false;
								keep_alive = false;
							} else if (chunk_size == 0) {
								keep_reading = false;
							}
						}

						bytes_in_buffer = 0;
						session->data_sent = true;
				}
		}
	} while (keep_reading);

	if (send_in_chunks && (result == 200)) {
		send_chunk(session, NULL, 0);
	}

	session->time = time(NULL);

#ifdef ENABLE_CACHE
	if (cache_buffer != NULL) {
		add_rproxy_output_to_cache(session, cache_buffer, cache_size, cache_time);
		clear_free(cache_buffer, cache_size);
	}
#endif

	if (keep_alive == false) {
		/* Close connection to webserver
		 */
#ifdef ENABLE_SSL
		if (webserver.use_ssl) {
			ssl_close(&(webserver.ssl));
		}
#endif
		close(webserver.socket);
	} else if (session->rproxy_kept_alive == false) {
		/* Keep connection alive
		 */
		memcpy(&(session->rproxy_addr), &(rproxy->ip_addr), sizeof(t_ip_addr));
		session->rproxy_port = rproxy->port;
		session->rproxy_socket = webserver.socket;
#ifdef ENABLE_SSL
		session->rproxy_use_ssl = webserver.use_ssl;
		if (session->rproxy_use_ssl) {
			memcpy(&(session->rproxy_ssl), &(webserver.ssl), sizeof(ssl_context));
		}
#endif
	}

	session->rproxy_kept_alive = keep_alive;

	return result;
}
#endif
