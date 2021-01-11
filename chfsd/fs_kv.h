/* this file is internal and only used by fs_kv.c and fs_server_kv.c */

struct inode {
	uint32_t mode;
	uint32_t uid, gid;
	uint32_t msize;
	uint64_t size;
	uint64_t chunk_size;
	struct timespec mtime, ctime;
};

static int32_t fs_msize = sizeof(struct inode);
