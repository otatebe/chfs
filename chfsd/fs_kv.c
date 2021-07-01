#include <margo.h>
#include "ring_types.h"
#include "kv_types.h"
#include "kv.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs.h"
#include "log.h"
#include "fs_kv.h"

static struct inode *
create_inode(uint32_t uid, uint32_t gid, uint32_t mode, size_t chunk_size,
	const void *buf, size_t size, off_t offset)
{
	struct inode *inode;
	struct timespec ts;

	if (offset > chunk_size)
		return (NULL);
	if (offset + size > chunk_size)
		size = chunk_size - offset;
	if (size == 0)
		offset = 0;

	if (buf == NULL)
		inode = calloc(fs_msize + chunk_size, 1);
	else
		inode = malloc(fs_msize + chunk_size);
	if (inode == NULL)
		return (NULL);

	inode->mode = mode;
	inode->uid = uid;
	inode->gid = gid;
	inode->msize = fs_msize;
	inode->size = offset + size;
	inode->chunk_size = chunk_size;
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	inode->mtime = inode->ctime = ts;
	if (buf) {
		void *base = (void *)inode + fs_msize;

		if (offset > 0)
			memset(base, 0, offset);
		memcpy(base + offset, buf, size);
		if (chunk_size > offset + size)
			memset(base + offset + size, 0,
				chunk_size - offset - size);
	}

	return (inode);
}

static int
fs_inode_create_data(char *key, size_t key_size, int32_t uid, int32_t gid,
	mode_t mode, size_t chunk_size, const void *buf, size_t size, off_t off)
{
	struct inode *inode;
	int r;
	static const char diag[] = "fs_inode_create";

	inode = create_inode(uid, gid, mode, chunk_size, buf, size, off);
	if (inode == NULL)
		return (KV_ERR_NO_MEMORY);
	r = kv_put(key, key_size, inode, fs_msize + chunk_size);
	free(inode);
	if (r != KV_SUCCESS)
		log_error("%s: %s", diag, kv_err_string(r));
	return (r);
}

int
fs_inode_create(char *key, size_t key_size, int32_t uid, int32_t gid,
	mode_t mode, size_t chunk_size, const char *buf, size_t size)
{
	return (fs_inode_create_data(key, key_size, uid, gid, mode, chunk_size,
			buf, size, 0));
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
	stat->mtime = inode.mtime;
	stat->ctime = inode.ctime;
	return (KV_SUCCESS);
}

int
fs_inode_write(char *key, size_t key_size, const void *buf, size_t *size,
	off_t offset, mode_t mode, size_t chunk_size)
{
	struct inode inode;
	size_t s = fs_msize, ss;
	int r;
	static const char diag[] = "fs_inode_write";

	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS) {
		r = fs_inode_create_data(key, key_size, 0, 0, mode, chunk_size,
			buf, *size, offset);
		if (r != KV_SUCCESS)
			log_error("%s: %s", diag, kv_err_string(r));
		return (r);
	}
	r = kv_update(key, key_size, fs_msize + offset, (void *)buf, size);
	if (r == KV_SUCCESS) {
		s = offset + *size;
		ss = sizeof(s);
		if (inode.size < s)
			r = kv_update(key, key_size,
				offsetof(struct inode, size), &s, &ss);
	}
	if (r != KV_SUCCESS)
		log_error("%s: %s", diag, kv_err_string(r));
	return (r);
}

int
fs_inode_read(char *key, size_t key_size, void *buf, size_t *size,
	off_t offset)
{
	struct inode inode;
	size_t s = fs_msize, ss = *size;
	int r;

	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS)
		return (r);
	if (offset + *size > inode.size)
		ss = inode.size - offset;
	if (ss <= 0) {
		*size = 0;
		return (KV_SUCCESS);
	}
	r = kv_pget(key, key_size, fs_msize + offset, buf, &ss);
	if (r == KV_SUCCESS)
		*size = ss;
	return (r);
}

int
fs_inode_remove(char *key, size_t key_size)
{
	return (kv_remove(key, key_size));
}
