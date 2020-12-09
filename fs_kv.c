#include <margo.h>
#include "ring_types.h"
#include "kv_types.h"
#include "kv.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs.h"

struct inode {
	uint32_t mode;
	uint32_t uid, gid;
	uint32_t msize;
	uint64_t size;
	uint64_t chunk_size;
	struct timespec mtime, ctime;
};

static int32_t fs_msize = sizeof(struct inode);

int
fs_inode_msize()
{
	return (fs_msize);
}

static struct inode *
create_inode(uint32_t uid, uint32_t gid, uint32_t mode, size_t chunk_size)
{
	struct inode *inode;
	struct timespec ts;

	inode = calloc(fs_msize + chunk_size, 1);
	if (inode == NULL)
		return (NULL);

	inode->mode = mode;
	inode->uid = uid;
	inode->gid = gid;
	inode->msize = fs_msize;
	inode->size = 0;
	inode->chunk_size = chunk_size;
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	inode->mtime = inode->ctime = ts;

	return (inode);
}

int
fs_inode_create(char *key, size_t key_size, int32_t uid, int32_t gid,
	mode_t mode, size_t chunk_size)
{
	struct inode *inode;
	int r;

	inode = create_inode(uid, gid, mode, chunk_size);
	if (inode == NULL)
		return (KV_ERR_NO_MEMORY);
	r = kv_put(key, key_size, inode, fs_msize + chunk_size);
	free(inode);
	return (r);
}

int
fs_inode_stat(char *key, size_t key_size, struct fs_stat *stat)
{
	struct inode inode;
	size_t s;
	int r;

	s = fs_msize;
	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS)
		return (r);
	stat->mode = inode.mode;
	stat->uid = inode.uid;
	stat->gid = inode.gid;
	stat->size = inode.size;
	stat->chunk_size = inode.chunk_size;
	stat->mtime.sec = inode.mtime.sec;
	stat->mtime.nsec = inode.mtime.nsec;
	stat->ctime.sec = inode.ctime.sec;
	stat->ctime.nsec = inode.ctime.nsec;
	return (KV_SUCCESS);
}

int
fs_inode_write(char *key, size_t key_size, const void *buf, size_t *size,
	off_t offset, mode_t mode, size_t chunk_size)
{
	struct inode inode;
	size_t s = fs_msize, ss;
	int r;

	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS) {
		r = fs_inode_create(key, key_size, 0, 0, mode, chunk_size);
		inode.size = 0;
	}
	if (r != KV_SUCCESS)
		return (r);
	r = kv_update(key, key_size, fs_msize + offset, (void *)buf, size);
	if (r == KV_SUCCESS) {
		s = offset + *size;
		ss = sizeof(s);
		if (inode.size < s)
			r = kv_update(key, key_size,
				offsetof(struct inode, size), &s, &ss);
	}
	return (r);
}

int
fs_inode_read(char *key, size_t key_size, void *buf, size_t *size,
	off_t offset)
{
	return (kv_pget(key, key_size, fs_msize + offset, buf, size));
}

int
fs_inode_remove(char *key, size_t key_size)
{
	return (kv_remove(key, key_size));
}
