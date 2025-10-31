#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "file.h"
#include "log.h"

#define DIR_LEVEL 20

static int
fs_mkdir(char *path, mode_t mode, int (*func)(const char *))
{
	int r;

	r = mkdir(path, mode);
	if (r == 0 && func)
		func(path);
	return (r);
}

int
fs_mkdir_p(char *path, mode_t mode, int (*func)(const char *))
{
	int r, p = strlen(path) - 1, pos[DIR_LEVEL], i;
	static const char diag[] = "fs_mkdir_p";

	log_debug("%s: %s", diag, path);
	r = fs_mkdir(path, mode, func);
	if (r == 0 || errno != ENOENT)
		return (r);
	while (p > 0 && path[p] == '/')
		--p;
	for (i = 0; i < DIR_LEVEL; ++i) {
		while (p > 0 && path[p] != '/')
			--p;
		if (p == 0)
			return (-1);
		pos[i] = p;
		path[p] = '\0';

		log_debug("%s: [%d] %s", diag, i, path);
		r = fs_mkdir(path, mode, func);
		if (r == -1) {
			if (errno == ENOENT)
				continue;
			if (errno != EEXIST)
				return (r);
		}
		for (; i >= 0; --i) {
			path[pos[i]] = '/';
			r = fs_mkdir(path, mode, func);
			if (r == -1 && errno != EEXIST)
				return (r);
		}
		return (0);
	}
	return (-1);
}

char *
fs_dirname(const char *path)
{
	size_t p = strlen(path) - 1;
	char *r;
	static const char diag[] = "fs_dirname";

	while (p > 0 && path[p] != '/')
		--p;
	if (p == 0)
		return (NULL);

	r = malloc(p + 1);
	if (r == NULL) {
		log_error("%s: no memory", diag);
		return (NULL);
	}
	strncpy(r, path, p);
	r[p] = '\0';
	log_debug("%s: path %s dirname %s", diag, path, r);
	return (r);
}

void
fs_mkdir_parent(const char *path, int (*func)(const char *))
{
	char *d = fs_dirname(path);

	if (d != NULL) {
		/* fs_mkdir_p() may fail due to race condition */
		fs_mkdir_p(d, 0755, func);
		free(d);
	}
}
