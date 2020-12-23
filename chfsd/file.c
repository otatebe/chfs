#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include "file.h"
#include "log.h"

#define DIR_LEVEL 20

int
mkdir_p(char *path, mode_t mode)
{
	int r, p = strlen(path) - 1, pos[DIR_LEVEL], i;

	log_debug("mkdir_p: %s", path);
	r = mkdir(path, mode);
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

		log_debug("mkdir_p: [%d] %s", i, path);
		r = mkdir(path, mode);
		if (r == -1) {
			if (errno == ENOENT)
				continue;
			if (errno != EEXIST)
				return (r);
		}
		for (; i >= 0; --i) {
			path[pos[i]] = '/';
			r = mkdir(path, mode);
			if (r == -1 && errno != EEXIST)
				return (r);
		}
		return (0);
	}
	return (-1);
}
