struct fs_stat;
struct dirent;

void fs_inode_init(char *db_dir, int niothreads);
int fs_inode_create(char *key, size_t key_size, int32_t uid, int32_t gid,
	mode_t mode, size_t chunk_size, const char *buf, size_t size);
int fs_inode_stat(char *key, size_t key_size, struct fs_stat *stat);
int fs_inode_write(char *key, size_t key_size, const void *buf,
	size_t *size, off_t offset, mode_t mode, size_t chunk_size);
int fs_inode_read(char *key, size_t key_size, void *buf, size_t *size,
	off_t offset);
int fs_inode_remove(char *key, size_t key_size);
int fs_inode_unlink_chunk_all(char *path);
int fs_inode_readdir(char *path, void (*cb)(struct dirent *, void *),
	void *arg);
