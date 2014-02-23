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
#include <dirent.h>
#include "global.h"
#include "libstr.h"
#include "libfs.h"
#include "filehashes.h"
#include "polarssl/version.h"
#if POLARSSL_VERSION_NUMBER >= 0x01030000
#include "polarssl/sha256.h"
#else
#include "polarssl/sha2.h"
#define sha256_file sha2_file
#endif

void sha2_bin2hex(unsigned char bin[SHA_HASH_SIZE], char hex[FILE_HASH_SIZE + 1]) {
	int i;

	for (i = 0; i < SHA_HASH_SIZE; i++) {
		sprintf(&hex[2 * i], "%02x", bin[i]);
	}
	hex[FILE_HASH_SIZE] = '\0';
}

t_file_hash *read_file_hashes(char *hashes_file) {
	FILE *fp;
	char line[1024], *filename, *hash;
	t_file_hash *file_hash = NULL, *new;

	if ((fp = fopen(hashes_file, "r")) == NULL) {
		return NULL;
	}

	while (fgets(line, 1023, fp) != NULL) {
		line[1023] = '\0';
		if (strlen(line) > 1020) {
			fclose(fp);
			return NULL;
		}

		if (split_string(line, &hash, &filename, ':') != 0) {
			fclose(fp);
			return NULL;
		}

		if ((new = (t_file_hash*)malloc(sizeof(t_file_hash))) == NULL) {
			fclose(fp);
			return NULL;
		}

		if (strlen(hash) != FILE_HASH_SIZE) {
			free(new);
			fclose(fp);
			return NULL;
		}
		memcpy(new->hash, hash, SHA_HASH_SIZE + 1);

		if ((new->filename = strdup(filename)) == NULL) {
			free(new);
			fclose(fp);
			return NULL;
		}
		new->filename_len = strlen(new->filename);

		new->next = file_hash;
		file_hash = new;
	}

	fclose(fp);

	return file_hash;
}

static int memrcmp(char *s1, char *s2, size_t len) {
	if (len == 0) {
		return 0;
	}

	s1 += (len - 1);
	s2 += (len - 1);

	do {
		if (*s1 != *s2) {
			return *s1 - *s2;
		}

		s1--;
		s2--;
		len--;
	} while (len > 0);

	return 0;
}

static t_file_hash *search_file(char *filename, t_file_hash *file_hashes) {
	size_t len;

	len = strlen(filename);
	while (file_hashes != NULL) {
		if (len == file_hashes->filename_len) {
			if (memrcmp(filename, file_hashes->filename, len) == 0) {
				return file_hashes;
			}
		}
		file_hashes = file_hashes->next;
	}

	return NULL;
}

bool file_hash_match(char *filename, t_file_hash *file_hashes) {
	t_file_hash *file_hash;
	unsigned char bin_hash[SHA_HASH_SIZE];
	char hex_hash[FILE_HASH_SIZE];

	if ((file_hash = search_file(filename, file_hashes)) == NULL) {
		return false;
	}
	if (sha256_file(filename, bin_hash, 0) != 0) {
		return false;
	}
	sha2_bin2hex(bin_hash, hex_hash);

	if (memcmp(file_hash->hash, hex_hash, SHA_HASH_SIZE) != 0) {
		return false;
	}

	return true;
}

int print_file_hashes(char *directory) {
	char cwd[1024];
	DIR *dp;
	struct dirent *fileinfo;
	unsigned char bin_hash[SHA_HASH_SIZE];
	char hex_hash[FILE_HASH_SIZE];

	if (chdir(directory) != 0) {
		return -1;
	}

	if (getcwd(cwd, 1024) == NULL) {
		return -1;
	}
	cwd[1023] = '\0';

	if ((dp = opendir(".")) == NULL) {
		return -1;
	}

	while ((fileinfo = readdir(dp)) != NULL) {
		if (fileinfo->d_name[0] == '.') {
			continue;
		}

		switch (is_directory(fileinfo->d_name)) {
			case yes:
				print_file_hashes(fileinfo->d_name);
				break;
			case no:
				if (sha256_file(fileinfo->d_name, bin_hash, 0) != 0) {
					return -1;
				}
				sha2_bin2hex(bin_hash, hex_hash);

				printf("%s : %s/%s\n", hex_hash, cwd, fileinfo->d_name);
				break;
			default:
				break;
		}

	}

	if (chdir("..") != 0) {
		return -1;
	}

	return 0;
}
