#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <margo.h>
#include "kv_err.h"
#include "kv.h"

static ABT_mutex mutex;
static int kv_num = 0, kv_size = 0;
static struct kvpair {
	int key_size, value_size;
	void *key, *value;
} *kvpair;

#define KV_NUM_INIT	100

void
kv_init(char *d, char *e, char *p, uint64_t s)
{
	ABT_mutex_create(&mutex);
	if (kv_size < KV_NUM_INIT)
		kv_size = KV_NUM_INIT;
	kvpair = malloc(kv_size * sizeof(*kvpair));
	assert(kvpair);
}

void
kv_term()
{}

static struct kvpair *
kv_get_internal_unlocked(void *key, size_t key_size);

static void
kv_expend()
{
	struct kvpair *tmp;

	if (kv_num >= kv_size) {
		kv_size *= 2;
		tmp = realloc(kvpair, kv_size * sizeof(*kvpair));
		assert(tmp);
		kvpair = tmp;
	}
}

int
kv_put(void *key, size_t key_size, void *value, size_t value_size)
{
	struct kvpair *tmp;

	ABT_mutex_lock(mutex);
	tmp = kv_get_internal_unlocked(key, key_size);
	if (tmp) {
		ABT_mutex_unlock(mutex);
		printf("duplicated entry: key=%s\n", (char *)key);
		return (KV_ERR_EXIST);
	}
	printf("local put: key=%s value=%s\n", (char *)key, (char *)value);
	kv_expend();

	tmp = &kvpair[kv_num];
	tmp->key_size = key_size;
	tmp->key = malloc(key_size);
	assert(tmp->key);
	memcpy(tmp->key, key, key_size);

	tmp->value_size = value_size;
	tmp->value = malloc(value_size);
	assert(tmp->value);
	memcpy(tmp->value, value, value_size);
	++kv_num;
	ABT_mutex_unlock(mutex);
	return (KV_SUCCESS);
}

int
kv_put_addr(void *key, size_t key_size, void **value, size_t value_size)
{
	struct kvpair *tmp;

	ABT_mutex_lock(mutex);
	tmp = kv_get_internal_unlocked(key, key_size);
	if (tmp) {
		ABT_mutex_unlock(mutex);
		printf("duplicated entry: key=%s\n", (char *)key);
		return (KV_ERR_EXIST);
	}
	printf("local put addr: key=%s\n", (char *)key);
	kv_expend();

	tmp = &kvpair[kv_num];
	tmp->key_size = key_size;
	tmp->key = malloc(key_size);
	assert(tmp->key);
	memcpy(tmp->key, key, key_size);

	tmp->value_size = value_size;
	tmp->value = malloc(value_size);
	assert(tmp->value);
	*value = tmp->value;
	++kv_num;
	ABT_mutex_unlock(mutex);
	return (KV_SUCCESS);
}

static struct kvpair *
kv_get_internal_unlocked(void *key, size_t key_size)
{
	int i;

	for (i = 0; i < kv_num; ++i)
		if (memcmp(key, kvpair[i].key, key_size) == 0)
			break;
	if (i == kv_num)
		return (NULL);
	return (&kvpair[i]);
}

static int
kv_get_unlocked(void *key, size_t key_size, void *value, size_t *value_size)
{
	struct kvpair *tmp;

	tmp = kv_get_internal_unlocked(key, key_size);
	if (tmp == NULL)
		return (KV_ERR_NO_ENTRY);
	if (*value_size > tmp->value_size)
		*value_size = tmp->value_size;
	memcpy(value, tmp->value, *value_size);
	return (KV_SUCCESS);
}

int
kv_get(void *key, size_t key_size, void *value, size_t *value_size)
{
	int r;

	printf("local get: key=%s\n", (char *)key);
	ABT_mutex_lock(mutex);
	r = kv_get_unlocked(key, key_size, value, value_size);
	ABT_mutex_unlock(mutex);
	return (r);
}

int
kv_get_cb(void *key, size_t key_size, void (*cb)(const char *, size_t, void *),
	void *arg)
{
	struct kvpair *tmp;

	printf("local get cb: key=%s\n", (char *)key);
	ABT_mutex_lock(mutex);
	tmp = kv_get_internal_unlocked(key, key_size);
	if (tmp == NULL) {
		ABT_mutex_unlock(mutex);
		return (KV_ERR_NO_ENTRY);
	}
	cb(tmp->value, tmp->value_size, arg);
	ABT_mutex_unlock(mutex);
	return (KV_SUCCESS);
}
