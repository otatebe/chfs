#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <abt.h>
#include "murmur3.h"
#include "log.h"

typedef uint32_t HASH_T[1];
#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_MODULO(a, b) (a[0] % (b))

#define LOCK_TABLE_SIZE	16384

static ABT_mutex_memory kv_lock_mutex[LOCK_TABLE_SIZE] = {
	[0 ... LOCK_TABLE_SIZE - 1] = ABT_MUTEX_INITIALIZER
};

static int
key_index(char *key, size_t key_size)
{
	int index = 0, slen = strlen(key) + 1;

	if (slen < key_size)
		index = atoi(key + slen);
	return (index);
}

static void
timespec_sub(struct timespec *t1, struct timespec *t2, struct timespec *t3)
{
	t3->tv_nsec = t2->tv_nsec - t1->tv_nsec;
	if (t3->tv_nsec < 0) {
		t3->tv_nsec += 1000000000;
		--t2->tv_sec;
	}
	t3->tv_sec = t2->tv_sec - t1->tv_sec;
}

void
kv_lock(char *key, size_t key_size, const char *diag, size_t size, off_t off)
{
	HASH_T hash;
	int n, r, index;
	struct timespec ts1, ts2, ts3;
	ABT_mutex mutex;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&kv_lock_mutex[n]);
	r = ABT_mutex_trylock(mutex);
	if (r == ABT_ERR_MUTEX_LOCKED) {
		clock_gettime(CLOCK_REALTIME, &ts1);
		ABT_mutex_lock(mutex);
		clock_gettime(CLOCK_REALTIME, &ts2);
		index = key_index(key, key_size);
		timespec_sub(&ts1, &ts2, &ts3);
		log_info("kv_lock (%s): %s:%d size %lu offset %lu "
			"wait %ld.%09ld seconds", diag, key, index, size, off,
			ts3.tv_sec, ts3.tv_nsec);
	}
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
