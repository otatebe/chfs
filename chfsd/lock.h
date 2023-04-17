void kv_lock(char *key, size_t key_size,
	const char *diag, size_t size, off_t off);
void kv_unlock(char *key, size_t key_size);
void kv_lock_flush_read(char *key, size_t key_size,
	const char *diag, size_t size, off_t off);
int kv_lock_flush_write(char *key, size_t key_size,
	const char *diag, size_t size, off_t off);
void kv_unlock_flush(char *key, size_t key_size);
