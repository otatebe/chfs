int backend_write(char *dst, int flags, mode_t mode,
	const char *buf, size_t size, off_t off);
int backend_write_key(const char *key, mode_t mode,
	const char *buf, size_t size, off_t off);
int backend_stat(char *path, size_t psize, size_t chunk_size,
	struct fs_stat *st);
char *backend_read(char *path, size_t psize, size_t chunk_size,
	struct fs_stat *st, size_t *size);
