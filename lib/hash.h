/* thread-free version of hash table */

typedef struct hash hash_t;

hash_t *hash_make(int size);
void **hash_get(hash_t *tbl, char *key, size_t key_size);
void **hash_find(hash_t *tbl, char *key, size_t key_size);
int hash_release(hash_t *tbl, void **data);
void *hash_delete(hash_t *tbl, void **dataptr);
int hash_operate(
	hash_t *tbl, void (*ptr)(void *, size_t, void **, void *), void *usr_arg);
