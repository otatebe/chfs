struct shash;

struct shash *shash_make(int size);
void **shash_get(struct shash *tbl, const char *key, size_t key_size);
void **shash_find(struct shash *tbl, const char *key, size_t key_size);
void *shash_delete(struct shash *tbl, void **dataptr);
int shash_operate(struct shash *tbl,
	void (*ptr)(void *, size_t, void **, void *), void *usr_arg);
void shash_free(struct shash *tbl);
