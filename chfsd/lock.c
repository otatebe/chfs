#include <string.h>
#include <time.h>
#include <abt.h>
#include "timespec.h"
#include "murmur3.h"
#include "key.h"
#include "log.h"

typedef uint32_t HASH_T[1];
#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_MODULO(a, b) (a[0] % (b))

#define LOCK_TABLE_SIZE	16381

static ABT_mutex_memory kv_lock_mutex[LOCK_TABLE_SIZE] = {
	[0 ... LOCK_TABLE_SIZE - 1] = ABT_RECURSIVE_MUTEX_INITIALIZER
};

#define KEYBUF_SIZE 256

static struct {
	const char *diag;
	char key[KEYBUF_SIZE];
	size_t key_size;
	struct timespec lock, unlock;
	int lockcount;
	int flush;
	int dirty_flush;
} holder[LOCK_TABLE_SIZE];

static int
kv_lock_internal(char *key, size_t key_size, const char *diag, size_t size,
	off_t off)
{
	HASH_T hash;
	int n, r, index1, index2;
	struct timespec ts1, ts2, ts3, ts4, ts5;
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
		timespec_sub(&holder[n].lock, &holder[n].unlock, &ts4);
		timespec_sub(&holder[n].unlock, &ts2, &ts5);
		if (ts3.tv_sec > 0)
			log_notice("kv_lock (%s): %s:%d size %lu offset %lu "
				"wait %ld.%09ld sec for lock of %s:%d (%s) "
				"hold %ld.%09ld sec before %ld.%09ld sec",
				diag, key, index1, size, off,
				ts3.tv_sec, ts3.tv_nsec,
				holder[n].key, index2, holder[n].diag,
				ts4.tv_sec, ts4.tv_nsec,
				ts5.tv_sec, ts5.tv_nsec);
		else
			log_info("kv_lock (%s): %s:%d size %lu offset %lu "
				"wait %ld.%09ld sec for lock of %s:%d (%s) "
				"hold %ld.%09ld sec before %ld.%09ld sec",
				diag, key, index1, size, off,
				ts3.tv_sec, ts3.tv_nsec,
				holder[n].key, index2, holder[n].diag,
				ts4.tv_sec, ts4.tv_nsec,
				ts5.tv_sec, ts5.tv_nsec);
	}
	++holder[n].lockcount;
	if (holder[n].lockcount == 1) {
		holder[n].diag = diag;
		if (key_size > KEYBUF_SIZE)
			key_size = KEYBUF_SIZE;
		memcpy(holder[n].key, key, key_size);
		if (key_size == KEYBUF_SIZE)
			holder[n].key[key_size - 1] = '\0';
		holder[n].key_size = key_size;
		clock_gettime(CLOCK_REALTIME, &holder[n].lock);
	}
	return (n);
}

void
kv_lock(char *key, size_t key_size, const char *diag, size_t size, off_t off)
{
	int n;

	n = kv_lock_internal(key, key_size, diag, size, off);
	if (holder[n].flush > 0)
		holder[n].dirty_flush = 1;
}

static void
kv_unlock_internal(char *key, size_t key_size)
{
	HASH_T hash;
	int n;
	ABT_mutex mutex;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&kv_lock_mutex[n]);
	--holder[n].lockcount;
	if (holder[n].lockcount == 0)
		clock_gettime(CLOCK_REALTIME, &holder[n].unlock);
	ABT_mutex_unlock(mutex);
}

void
kv_unlock(char *key, size_t key_size)
{
	kv_unlock_internal(key, key_size);
}

void
kv_lock_flush_start(char *key, size_t key_size, const char *diag, size_t size,
	off_t off)
{
	int n;

	n = kv_lock_internal(key, key_size, diag, size, off);
	++holder[n].flush;
	kv_unlock_internal(key, key_size);
}

int
kv_lock_flush(char *key, size_t key_size, const char *diag, size_t size,
	off_t off)
{
	int n;

	n = kv_lock_internal(key, key_size, diag, size, off);
	return (holder[n].dirty_flush);
}

void
kv_unlock_flush(char *key, size_t key_size)
{
	HASH_T hash;
	int n;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	--holder[n].flush;
	if (holder[n].flush == 0)
		holder[n].dirty_flush = 0;
	kv_unlock_internal(key, key_size);
}
