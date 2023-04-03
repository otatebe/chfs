#include <abt.h>
#include "murmur3.h"

typedef uint32_t HASH_T[1];
#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_MODULO(a, b) (a[0] % (b))

#define LOCK_TABLE_SIZE	16384

static ABT_mutex_memory kv_lock_mutex[LOCK_TABLE_SIZE] = {
	[0 ... LOCK_TABLE_SIZE - 1] = ABT_MUTEX_INITIALIZER
};

void
kv_lock(char *key, size_t key_size)
{
	HASH_T hash;
	int n;
	ABT_mutex mutex;

	HASH(key, key_size, hash);
	n = HASH_MODULO(hash, LOCK_TABLE_SIZE);
	mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&kv_lock_mutex[n]);
	ABT_mutex_lock(mutex);
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
