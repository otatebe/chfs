struct stat;

int chfs_init(const char *server);
int chfs_term();
void chfs_set_chunk_size(int chunk_size);
void chfs_set_get_rdma_thresh(int thresh);
void chfs_set_rpc_timeout_msec(int timeout);
void chfs_set_node_list_cache_timeout(int timeout);

int chfs_create(const char *path, int32_t flags, mode_t mode);
int chfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
	int chunk_size);
int chfs_open(const char *path, int32_t flags);
int chfs_close(int fd);
ssize_t chfs_pwrite(int fd, const void *buf, size_t size, off_t offset);
ssize_t chfs_write(int fd, const void *buf, size_t size);
ssize_t chfs_pread(int fd, void *buf, size_t size, off_t offset);
ssize_t chfs_read(int fd, void *buf, size_t size);
int chfs_fsync(int fd);
int chfs_unlink(const char *path);
int chfs_mkdir(const char *path, mode_t mode);
int chfs_rmdir(const char *path);
int chfs_stat(const char *path, struct stat *st);
int chfs_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t));
