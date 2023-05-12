#include <stdlib.h>
#include <time.h>
#include <margo.h>
#include "path.h"
#include "ring_types.h"
#include "ring_list.h"
#include "kv_types.h"
#include "kv.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs.h"
#include "file.h"
#include "timespec.h"
#include "log.h"
#include "fs_kv.h"
#include "lock.h"

static struct inode *
create_inode_all(uint32_t uid, uint32_t gid, uint32_t mode, size_t chunk_size,
	struct timespec *mtime, struct timespec *ctime,
	const void *buf, size_t size, off_t offset)
{
	struct inode *inode;

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

	inode->mode = MODE_MASK(mode);
	inode->uid = uid;
	inode->gid = gid;
	inode->msize = fs_msize;
	inode->flags = FLAGS_FROM_MODE(mode);
	if (!(inode->flags & CHFS_FS_CACHE))
		inode->flags |= CHFS_FS_DIRTY;
	inode->size = offset + size;
	inode->chunk_size = chunk_size;
	inode->mtime = *mtime;
	inode->ctime = *ctime;
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

static struct inode *
create_inode(uint32_t uid, uint32_t gid, uint32_t mode, size_t chunk_size,
	const void *buf, size_t size, off_t offset)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	return (create_inode_all(uid, gid, mode, chunk_size, &ts, &ts,
			buf, size, offset));
}

#define IS_MODE_CACHE(mode)	(FLAGS_FROM_MODE(mode) & CHFS_FS_CACHE)

static int
fs_inode_create_data(char *key, size_t key_size, uint32_t uid, uint32_t gid,
	uint32_t mode, size_t chunk_size, const void *buf, size_t size,
	off_t off)
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
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
	else if (!IS_MODE_CACHE(mode))
		fs_inode_flush_enq(key, key_size);
	return (r);
}

int
fs_inode_create(char *key, size_t key_size, uint32_t uid, uint32_t gid,
	uint32_t mode, size_t chunk_size, const void *buf, size_t size)
{
	return (fs_inode_create_data(key, key_size, uid, gid, mode, chunk_size,
			buf, size, 0));
}

int
fs_inode_create_stat(char *key, size_t key_size, struct fs_stat *st,
	const void *buf, size_t size)
{
	int r;
	static const char diag[] = "fs_inode_create_stat";

	r = kv_put(key, key_size, (void *)buf, size);
	if (r != KV_SUCCESS)
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
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
	if (fs_msize != inode.msize)
		return (KV_ERR_METADATA_SIZE_MISMATCH);
	stat->mode = MODE_FLAGS(inode.mode, inode.flags);
	stat->uid = inode.uid;
	stat->gid = inode.gid;
	stat->size = inode.size;
	stat->chunk_size = inode.chunk_size;
	stat->mtime = inode.mtime;
	stat->ctime = inode.ctime;
	return (KV_SUCCESS);
}

static int
fs_inode_update_size(char *key, size_t key_size, size_t size)
{
	size_t ss;
	int r;
	static const char diag[] = "fs_inode_update_size";

	ss = sizeof(size);
	r = kv_update(key, key_size, offsetof(struct inode, size), &size, &ss);
	if (r != KV_SUCCESS)
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
	return (r);
}

static int
fs_inode_dirty(char *key, size_t key_size, uint16_t flags)
{
	size_t ss;
	int r;
	static const char diag[] = "fs_inode_dirty";

	if (flags & CHFS_FS_DIRTY)
		return (KV_SUCCESS);

	flags |= CHFS_FS_DIRTY;
	ss = sizeof(flags);
	r = kv_update(key, key_size, offsetof(struct inode, flags),
		&flags, &ss);
	if (r != KV_SUCCESS)
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
	return (r);
}

int
fs_inode_write(char *key, size_t key_size, const void *buf, size_t *size,
	off_t offset, uint32_t mode, size_t chunk_size)
{
	struct inode inode;
	size_t s = fs_msize;
	int r;
	static const char diag[] = "fs_inode_write";

	kv_lock(key, key_size, diag, *size, offset);
	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS) {
		r = fs_inode_create_data(key, key_size, 0, 0, mode, chunk_size,
			buf, *size, offset);
		kv_unlock(key, key_size);
		if (r != KV_SUCCESS)
			log_error("%s: %s: %s", diag, key, kv_err_string(r));
		return (r);
	}
	r = kv_update(key, key_size, fs_msize + offset, (void *)buf, size);
	if (r == KV_SUCCESS && !IS_MODE_CACHE(mode))
		r = fs_inode_dirty(key, key_size, inode.flags);
	if (r != KV_SUCCESS) {
		kv_unlock(key, key_size);
		log_error("%s: %s", diag, kv_err_string(r));
		return (r);
	}
	s = offset + *size;
	if (inode.size < s)
		r = fs_inode_update_size(key, key_size, s);
	kv_unlock(key, key_size);
	if (r != KV_SUCCESS)
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
	else if (!IS_MODE_CACHE(mode))
		fs_inode_flush_enq(key, key_size);
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
	if (offset + *size > inode.size) {
		if (offset >= inode.size) {
			*size = 0;
			return (KV_SUCCESS);
		}
		ss = inode.size - offset;
	}
	r = kv_pget(key, key_size, fs_msize + offset, buf, &ss);
	if (r == KV_SUCCESS)
		*size = ss;
	return (r);
}

int
fs_inode_truncate(char *key, size_t key_size, off_t len)
{
	struct inode inode;
	size_t s = fs_msize;
	int r;
	static const char diag[] = "fs_inode_truncate";

	kv_lock(key, key_size, diag, len, 0);
	r = kv_pget(key, key_size, 0, &inode, &s);
	if (r != KV_SUCCESS) {
		kv_unlock(key, key_size);
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
		return (r);
	}
	if (inode.chunk_size < len || len < 0) {
		kv_unlock(key, key_size);
		r = KV_ERR_OUT_OF_RANGE;
		log_error("%s: %s: %s", diag, key, kv_err_string(r));
		return (r);
	}
	if (inode.size != len) {
		r = fs_inode_update_size(key, key_size, len);
		if (r == KV_SUCCESS)
			r = fs_inode_dirty(key, key_size, inode.flags);
		kv_unlock(key, key_size);
		if (r != KV_SUCCESS)
			log_error("%s: %s: %s", diag, key, kv_err_string(r));
		else
			fs_inode_flush_enq(key, key_size);
	} else
		kv_unlock(key, key_size);
	return (r);
}

int
fs_inode_remove(char *key, size_t key_size)
{
	return (kv_remove(key, key_size));
}

int
fs_inode_unlink_chunk_all(char *path, int i)
{
	char p[PATH_MAX];
	int len, klen;

	if (path == NULL)
		return (0);
	len = strlen(path);
	strcpy(p, path);
	for (;; ++i) {
		sprintf(p + len + 1, "%d", i);
		klen = len + 1 + strlen(p + len + 1) + 1;
		if (!ring_list_is_in_charge(p, klen))
			continue;
		if (kv_remove(p, klen))
			break;
	}
	return (0);
}

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int
fs_err(int err)
{
	if (err >= 0)
		return (KV_SUCCESS);

	switch (-err) {
	case EEXIST:
		return (KV_ERR_EXIST);
	case ENOENT:
		return (KV_ERR_NO_ENTRY);
	case ENOMEM:
		return (KV_ERR_NO_MEMORY);
	case ENOTSUP:
		return (KV_ERR_NOT_SUPPORTED);
	default:
		log_notice("fs_err: %s", strerror(-err));
		return (KV_ERR_UNKNOWN);
	}
}

struct flush_cb_arg {
	char *dst;
	int index;
	void *key;
	size_t key_size;
};

#include <sys/stat.h>

void
flush_cb(const char *value, size_t value_size, void *arg)
{
	struct flush_cb_arg *a = arg;
	struct inode *inode = (void *)value;
	mode_t mode = MODE_MASK(inode->mode);
	int r, fd, flags, dirty_flush;
	struct timespec ts1, ts2, ts3;
	static const char diag[] = "flush_cb";

	log_debug("%s: dst=%s flags=%d size=%ld", diag, a->dst, inode->flags,
		inode->size);
	if (!(inode->flags & CHFS_FS_DIRTY)) {
		log_info("%s: clean", diag);
		return;
	}

	kv_lock_flush_start(a->key, a->key_size, diag, inode->size, 0);
	clock_gettime(CLOCK_REALTIME, &ts1);
	if (S_ISREG(mode))
		goto regular_file;

	if (S_ISDIR(mode))
		r = fs_mkdir_p(a->dst, mode);
	else if (S_ISLNK(mode)) {
		r = symlink(value + fs_msize, a->dst);
		if (r == -1) {
			fs_mkdir_parent(a->dst);
			r = symlink(value + fs_msize, a->dst);
		}
	} else {
		r = KV_ERR_NOT_SUPPORTED;
		goto done;
	}
	if (r == -1)
		r = fs_err(-errno);
	else
		r = KV_SUCCESS;
	goto done;

regular_file:
	flags = O_WRONLY;
	if (!(inode->flags & CHFS_FS_CACHE))
		flags |= O_CREAT;

	fd = open(a->dst, flags, mode);
	if (fd == -1) {
		fs_mkdir_parent(a->dst);
		fd = open(a->dst, flags, mode);
	}
	if (fd == -1)
		r = KV_ERR_NO_ENTRY;
	else {
		r = pwrite(fd, value + fs_msize, inode->size,
			a->index * inode->chunk_size);
		if (r == -1)
			r = fs_err(-errno);
		else if (r != inode->size) {
			log_info("%s: %s: %d of %ld bytes written", diag,
				a->dst, r, inode->size);
			r = KV_ERR_PARTIAL_WRITE;
		} else
			r = KV_SUCCESS;
		close(fd);
	}
done:
	clock_gettime(CLOCK_REALTIME, &ts2);
	dirty_flush = kv_lock_flush(a->key, a->key_size, diag, inode->size, 0);
	if (r == KV_SUCCESS && !dirty_flush) {
		inode->flags = (inode->flags & ~CHFS_FS_DIRTY) | CHFS_FS_CACHE;
		kv_persist(&inode->flags, sizeof(inode->flags));
	} else if (dirty_flush)
		log_info("%s: %s: dirty flush: %s", diag, a->dst,
				kv_err_string(r));
	else
		log_error("%s: %s: %s", diag, a->dst, kv_err_string(r));
	kv_unlock_flush(a->key, a->key_size);
	timespec_sub(&ts1, &ts2, &ts3);
	if (ts3.tv_sec > 0)
		log_notice("%s: %s:%d flush %ld.%09ld sec", diag,
			(char *)a->key, a->index, ts3.tv_sec, ts3.tv_nsec);
}

int
fs_inode_flush(void *key, size_t key_size)
{
	struct flush_cb_arg *arg;
	int index, keylen, r = KV_SUCCESS;
	char *dst;
	static const char diag[] = "flush";

	keylen = strlen(key) + 1;
	if (keylen == key_size)
		index = 0;
	else
		index = atoi(key + keylen);
	log_info("%s: %s:%d", diag, (char *)key, index);

	dst = path_backend(key);
	if (dst == NULL) {
		r = KV_ERR_NO_BACKEND_PATH;
		log_debug("%s: %s", diag, kv_err_string(r));
		return (r);
	}

	arg = malloc(sizeof(*arg));
	if (arg == NULL)
		r = KV_ERR_NO_MEMORY;
	else {
		arg->dst = dst;
		arg->index = index;
		arg->key = key;
		arg->key_size = key_size;
		r = kv_get_cb(key, key_size, flush_cb, arg);
		free(arg);
	}
	free(dst);
	if (r == KV_ERR_NO_ENTRY || r == KV_SUCCESS)
		log_info("%s: %s:%d: %s", diag, (char *)key, index,
			kv_err_string(r));
	else
		log_error("%s: %s:%d: %s", diag, (char *)key, index,
			kv_err_string(r));
	return (r);
}
