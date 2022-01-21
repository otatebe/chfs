#include <stdlib.h>
#include <string.h>
#include "log.h"

#define IS_SLASH_OR_NULL(c) (c == '/' || c == '\0')

static const char *
next_token(const char *p, int *s)
{
	const char *save_p = p;

	if (p[0] == '.') {
		if (IS_SLASH_OR_NULL(p[1])) {
			*s = 0;
			return (p + 1);
		}
		if (p[1] == '.' && IS_SLASH_OR_NULL(p[2])) {
			*s = -1;
			return (p + 2);
		}
	}
	while (!IS_SLASH_OR_NULL(*p))
		++p;
	*s = p - save_p;
	return (p);
}

static const char *
skip_slash(const char *p)
{
	while (*p == '/')
		++p;
	return (p);
}

#define MAX_DEPTH	50

char *
canonical_path(const char *path)
{
	struct entry {
		const char *s;
		int l;
	} d[MAX_DEPTH];
	int depth = 0, i, l;
	const char *p = path;
	char *pp;

	p = skip_slash(p);
	while (*p) {
		if (depth >= MAX_DEPTH)
			return (NULL);
		d[depth].s = p;
		p = next_token(p, &l);
		if (l > 0)
			d[depth++].l = l;
		else if (l == -1) {
			--depth;
			if (depth < 0)
				depth = 0;
		}
		p = skip_slash(p);
	}
	for (l = 0, i = 0; i < depth; ++i) {
		l += d[i].l;
		if (i < depth - 1)
			l++;
	}
	pp = malloc(l + 1);
	if (pp == NULL)
		return (NULL);
	for (l = 0, i = 0; i < depth; ++i) {
		strncpy(&pp[l], d[i].s, d[i].l);
		l += d[i].l;
		if (i < depth - 1)
			pp[l++] = '/';
	}
	pp[l] = '\0';
	return (pp);
}

static char *backend_path = NULL;
static int backend_pathlen;
static char *subdir_path = NULL;
static int subdir_pathlen;

void
path_set_subdir_path(const char *path)
{
	const char *p = skip_slash(path);

	if (p == NULL)
		return;
	log_debug("path_set_subdir_path: %s", p);
	subdir_path = strdup(p);
	subdir_pathlen = strlen(p);
}

void
path_set_backend_path(const char *path)
{
	if (path == NULL)
		return;
	log_debug("path_set_backend_path: %s", path);
	backend_path = strdup(path);
	backend_pathlen = strlen(path);
}

static const char *
skip_subdir(const char *path)
{
	const char *p = path;

	if (subdir_path == NULL)
		return (p);

	if (strncmp(subdir_path, p, subdir_pathlen) == 0)
		return (skip_slash(p + subdir_pathlen));

	return (p);
}

char *
path_backend(const char *path)
{
	const char *p;
	char *s;

	if (backend_path == NULL || path == NULL)
		return (NULL);

	p = skip_subdir(path);
	if (p == NULL)
		return (NULL);
	s = malloc(backend_pathlen + 1 + strlen(p) + 1);
	if (s == NULL)
		return (NULL);
	strcpy(s, backend_path);
	strcat(s, "/");
	strcat(s, p);

	return (s);
}
