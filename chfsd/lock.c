#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <abt.h>
#include "timespec.h"
#include "murmur3.h"
#include "log.h"

typedef uint32_t HASH_T[1];
#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_MODULO(a, b) (a[0] % (b))

#define LOCK_TABLE_SIZE	16381

static ABT_mutex_memory kv_lock_mutex[LOCK_TABLE_SIZE] = {
	[0 ... LOCK_TABLE_SIZE - 1] = ABT_MUTEX_INITIALIZER
};

#define KEYBUF_SIZE 256

static struct {
	const char *diag;
	char key[KEYBUF_SIZE];
	size_t key_size;
	struct timespec ts;
} holder[LOCK_TABLE_SIZE];

static int
key_index(char *key, size_t key_size)
{
	int index = 0, slen = strlen(key) + 1;

	if (slen < key_size)
		index = atoi(key + slen);
	return (index);
}

#define TIMEBUF_SIZE 256

void
kv_lock(char *key, size_t key_size, const char *diag, size_t size, off_t off)
{
	HASH_T hash;
	int n, r, index1, index2;
	struct timespec ts1, ts2, ts3, ts4;
	char time_str[TIMEBUF_SIZE];
	ABT_mutex mutex;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&kv_lock_mutex[n]);
	r = ABT_mutex_trylock(mutex);
	if (r == ABT_ERR_MUTEX_LOCKED) {
		clock_gettime(CLOCK_REALTIME, &ts1);
		ABT_mutex_lock(mutex);
		clock_gettime(CLOCK_REALTIME, &ts2);
		index1 = key_index(key, key_size);
		index2 = key_index(holder[n].key, holder[n].key_size);
		timespec_sub(&ts1, &ts2, &ts3);
		timespec_sub(&holder[n].ts, &ts2, &ts4);
		timespec_str(&holder[n].ts, time_str, TIMEBUF_SIZE);
		if (ts3.tv_sec > 0)
			log_notice("kv_lock (%s): %s:%d size %lu offset %lu "
				"wait %ld.%09ld seconds for lock of %s:%d (%s) "
				"at %s (%ld.%09ld seconds)", diag, key, index1,
				size, off, ts3.tv_sec, ts3.tv_nsec,
				holder[n].key, index2, holder[n].diag, time_str,
				ts4.tv_sec, ts4.tv_nsec);
		else
			log_info("kv_lock (%s): %s:%d size %lu offset %lu "
				"wait %ld.%09ld seconds for lock of %s:%d (%s) "
				"at %s (%ld.%09ld seconds)", diag, key, index1,
				size, off, ts3.tv_sec, ts3.tv_nsec,
				holder[n].key, index2, holder[n].diag, time_str,
				ts4.tv_sec, ts4.tv_nsec);
	}
	holder[n].diag = diag;
	if (key_size > KEYBUF_SIZE)
		key_size = KEYBUF_SIZE;
	memcpy(holder[n].key, key, key_size);
	if (key_size == KEYBUF_SIZE)
		holer[n].key[key_size - 1] = '\0';
	holder[n].key_size = key_size;
	clock_gettime(CLOCK_REALTIME, &holder[n].ts);
}

void
kv_unlock(char *key, size_t key_size)
{
	HASH_T hash;
	int n;
	ABT_mutex mutex;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&kv_lock_mutex[n]);
	ABT_mutex_unlock(mutex);
}
