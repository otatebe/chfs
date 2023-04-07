#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <libpmemkv.h>
#include "kv_err.h"
#include "kv.h"
#include "log.h"

static pmemkv_db *db = NULL;

static int
kv_err(int pmemkv_err)
{
	switch (pmemkv_err) {
	case PMEMKV_STATUS_OK:
		return (KV_SUCCESS);
	case PMEMKV_STATUS_NOT_FOUND:
		return (KV_ERR_NO_ENTRY);
	case PMEMKV_STATUS_OUT_OF_MEMORY:
		return (KV_ERR_NO_MEMORY);
	default:
		return (KV_ERR_UNKNOWN);
	}
}

void
kv_init(char *db_dir, char *engine, char *path, size_t size)
{
	pmemkv_config *cfg;
	char *p;
	int r;
	struct stat sb;
	static const char diag[] = "kv_init";

	if (db_dir == NULL || engine == NULL || path == NULL)
		log_fatal("%s: invalid argument", diag);

	p = malloc(strlen(db_dir) + 1 + strlen(path) + 1);
	if (p == NULL)
		log_fatal("%s: no memory", diag);
	if (stat(db_dir, &sb))
		log_fatal("%s: %s: %s",
			diag, db_dir, strerror(errno));
	if (S_ISDIR(sb.st_mode))
		sprintf(p, "%s/%s", db_dir, path);
	else
		sprintf(p, "%s", db_dir);
	log_info("kv_init: engine %s, path %s, size %ld", engine, p, size);

	cfg = pmemkv_config_new();
	if (cfg == NULL)
		log_fatal("%s (pmemkv_config_new): %s", diag,
			pmemkv_errormsg());
	r = pmemkv_config_put_string(cfg, "path", p);
	if (r != PMEMKV_STATUS_OK)
		log_fatal("%s (pmemkv_config_put_string:path): %s", diag,
			pmemkv_errormsg());

	r = pmemkv_open(engine, cfg, &db);
	if (r == PMEMKV_STATUS_OK)
		goto free_p;
	else
		log_debug("%s, continue", pmemkv_errormsg());

	cfg = pmemkv_config_new();
	if (cfg == NULL)
		log_fatal("%s (pmemkv_config_new): %s", diag,
			pmemkv_errormsg());
	r = pmemkv_config_put_string(cfg, "path", p);
	if (r != PMEMKV_STATUS_OK)
		log_fatal("%s (pmemkv_config_put_string:path): %s", diag,
			pmemkv_errormsg());
	r = pmemkv_config_put_uint64(cfg, "size", size);
	if (r != PMEMKV_STATUS_OK)
		log_fatal("%s (pmemkv_config_put_uint64:size): %s", diag,
			pmemkv_errormsg());
	r = pmemkv_config_put_uint64(cfg, "force_create", 1);
	if (r != PMEMKV_STATUS_OK)
		log_fatal("%s (pmemkv_config_put_uint64:force_create): %s",
			diag, pmemkv_errormsg());

	r = pmemkv_open(engine, cfg, &db);
	if (r != PMEMKV_STATUS_OK)
		log_fatal("%s: %s", diag, pmemkv_errormsg());
	log_debug("%s: created", p);
free_p:
	if (db == NULL)
		log_fatal("%s: db is NULL", diag);
	free(p);
}

void
kv_term()
{
	pmemkv_close(db);
}

int
kv_put(void *key, size_t key_size, void *value, size_t value_size)
{
	log_debug("local pmem put: key=%s", (char *)key);
	return (kv_err(pmemkv_put(db, key, key_size, value, value_size)));
}

int
kv_put_addr(void *key, size_t key_size, void **value, size_t value_size)
{
	log_info("local pmem put addr: not implemented");
	return (KV_ERR_NOT_SUPPORTED);
}

int
kv_get(void *key, size_t key_size, void *value, size_t *value_size)
{
	size_t o_size;
	int r;

	log_debug("local pmem get: key=%s", (char *)key);
	r = pmemkv_get_copy(db, key, key_size, value, *value_size, &o_size);
	if (r == PMEMKV_STATUS_OK)
		*value_size = o_size;
	return (kv_err(r));
}

int kv_get_cb(void *key, size_t key_size,
	void (*cb)(const char *, size_t, void *), void *arg)
{
	log_debug("local pmem get cb: key=%s", (char *)key);
	return (kv_err(pmemkv_get(db, key, key_size, cb, arg)));
}

struct arg {
	void *value;
	size_t off, size;
	int err;
};

static struct arg *
create_arg(size_t off, void *value, size_t value_size)
{
	struct arg *a;

	a = malloc(sizeof(*a));
	if (a == NULL)
		return (NULL);
	a->off = off;
	a->value = value;
	a->size = value_size;
	return (a);
}

static void
update_cb(const char *v, size_t size, void *a)
{
	struct arg *arg = a;
	char *value = (char *)v;

	if (arg->off > size)
		arg->size = 0;
	else if (arg->off + arg->size > size)
		arg->size = size - arg->off;
	if (arg->size == 0)
		return;
	value += arg->off;
	memcpy(value, arg->value, arg->size);
	/* XXX persist? */
}

int
kv_update(void *key, size_t key_size,
    size_t off, void *value, size_t *value_size)
{
	struct arg *a = create_arg(off, value, *value_size);
	int r;

	if (a == NULL)
		return (PMEMKV_STATUS_OUT_OF_MEMORY);
	r = kv_get_cb(key, key_size, update_cb, a);
	if (r == PMEMKV_STATUS_OK)
		*value_size = a->size;
	free(a);
	return (r);
}

static void
pget_cb(const char *v, size_t size, void *a)
{
	struct arg *arg = a;
	char *value = (char *)v;

	if (arg->off > size)
		arg->size = 0;
	else if (arg->off + arg->size > size)
		arg->size = size - arg->off;
	if (arg->size == 0)
		return;
	value += arg->off;
	memcpy(arg->value, value, arg->size);
	/* XXX persist? */
}

int
kv_pget(void *key, size_t key_size, size_t off, void *value, size_t *value_size)
{
	struct arg *a = create_arg(off, value, *value_size);
	int r;

	if (a == NULL)
		return (PMEMKV_STATUS_OUT_OF_MEMORY);
	r = kv_get_cb(key, key_size, pget_cb, a);
	if (r == PMEMKV_STATUS_OK)
		*value_size = a->size;
	free(a);
	return (r);
}

static void
get_size_cb(const char *v, size_t size, void *a)
{
	size_t *s = a;

	*s = size;
}

int
kv_get_size(void *key, size_t key_size, size_t *value_size)
{
	return (kv_get_cb(key, key_size, get_size_cb, value_size));
}

int
kv_remove(void *key, size_t key_size)
{
	return (kv_err(pmemkv_remove(db, key, key_size)));
}

int
kv_get_all_cb(int (*cb)(const char *, size_t, const char *, size_t, void *),
	void *arg)
{
	log_debug("local pmem get all cb");
	return (kv_err(pmemkv_get_all(db, cb, arg)));
}
