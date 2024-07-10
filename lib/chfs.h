struct stat;

int chfs_init(const char *server);
int chfs_initialized();
int chfs_term();
int chfs_term_without_sync();
int chfs_size();
const char *chfs_version();
void chfs_set_chunk_size(int chunk_size);
void chfs_set_buf_size(int buf_size);
void chfs_set_async_access(int enable);
void chfs_set_rdma_thresh(size_t thresh);
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
off_t chfs_seek(int fd, off_t off, int whence);
int chfs_fsync(int fd);
int chfs_truncate(const char *path, off_t len);
int chfs_unlink(const char *path);
int chfs_mkdir(const char *path, mode_t mode);
int chfs_rmdir(const char *path);
int chfs_stat(const char *path, struct stat *st);
int chfs_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t));
int chfs_readdir_index(const char *path, int index, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t));
int chfs_symlink(const char *target, const char *path);
int chfs_readlink(const char *path, char *buf, size_t size);
void chfs_sync();
void chfs_set_stagein_buf_size(int buf_size);
int chfs_stagein(const char *path);

#define CHFS_O_CACHE	(1 << 28)
#define CHFS_S_IFREP	(4 << 28)
