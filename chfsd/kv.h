void kv_init(char *db_dir, char *engine, char *path, size_t size);
void kv_term();

int kv_put(void *key, size_t key_size, void *value, size_t value_size);
int kv_put_addr(void *key, size_t key_size, void **value, size_t value_size);

int kv_get(void *key, size_t key_size, void *value, size_t *value_size);
int kv_get_cb(void *key, size_t key_size,
	void (*cb)(const char *, size_t, void *), void *arg);

int kv_update(void *key, size_t key_size, size_t off,
	void *value, size_t *value_size);
int kv_pget(void *key, size_t key_size, size_t off,
	void *value, size_t *value_size);

int kv_get_size(void *key, size_t key_size, size_t *value_size);

int kv_remove(void *key, size_t key_size);

int kv_get_all_cb(
	int (*cb)(const char *, size_t, const char *, size_t, void *),
	void *arg);
