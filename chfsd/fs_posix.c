#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <margo.h>
#include "config.h"
#include "ring_types.h"
#include "kv_types.h"
#include "kv.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs.h"
#include "file.h"
#include "log.h"

#ifndef USE_XATTR
struct metadata {
	size_t chunk_size;
};

static int msize = sizeof(struct metadata);
#endif

void
fs_inode_init(char *dir)
{
	int r;

	r = chdir(dir);
	if (r == -1 && errno == ENOENT) {
		r = mkdir_p(dir, 0755);
		if (r == 0)
			r = chdir(dir);
	}
	if (r == -1)
		log_fatal("%s: %s", dir, strerror(errno));

	log_info("fs_inode_init: path %s", dir);
}

/* key is modified */
static char *
key_to_path(char *key, size_t key_size)
{
	size_t klen = strlen(key);

	log_debug("key_to_path: key %s", key);
	if (klen + 1 < key_size)
		key[klen] = ':';
	while (*key && *key == '/')
		++key;
	if (*key == '\0')
		key = ".";
	log_debug("key_to_path: path %s", key);
	return (key);
}

static char *
fs_dirname(const char *path)
{
	size_t p = strlen(path) - 1;
	char *r;

	while (p > 0 && path[p] != '/')
		--p;
	if (p == 0)
		return (NULL);

	r = malloc(p + 1);
	if (r == NULL)
		return (NULL);
	strncpy(r, path, p);
	r[p] = '\0';
	log_debug("fs_dirname: path %s dirname %s", path, r);
	return (r);
}

#define FS_XATTR_CHUNK_SIZE "user.chunk_size"

static int
set_chunk_size(const char *path, size_t size)
{
	int r;
	static const char diag[] = "set_chunk_size";
#ifndef USE_XATTR
	int fd;
	struct metadata mdata;
#endif

#ifdef USE_XATTR
	r = setxattr(path, FS_XATTR_CHUNK_SIZE, &size, sizeof(size), 0);
	if (r == -1)
		log_error("%s: %s", diag, strerror(errno));
#else
	fd = r = open(path, O_WRONLY);
	if (fd == -1)
		log_error("%s: %s", diag, strerror(errno));
	else {
		mdata.chunk_size = size;
		r = write(fd, &mdata, msize);
		if (r == -1)
			log_error("%s (write): %s", diag, strerror(errno));
		else if (r != msize) {
			log_error("%s (write): %d of %d bytes written", diag,
				r, msize);
			r = -1;
		}
		close(fd);
	}
#endif
	return (r);
}

static int
get_chunk_size(const char *path, size_t *size)
{
	int r;
	static const char diag[] = "get_chunk_size";
#ifndef USE_XATTR
	int fd;
	struct metadata mdata;
#endif

#ifdef USE_XATTR
	r = getxattr(path, FS_XATTR_CHUNK_SIZE, size, sizeof(*size));
	if (r == -1)
		log_info("%s: %s", diag, strerror(errno));
#else
	fd = r = open(path, O_RDONLY);
	if (fd == -1)
		log_info("%s: %s", diag, strerror(errno));
	else {
		r = read(fd, &mdata, msize);
		if (r == -1)
			log_error("%s (read): %s", diag, strerror(errno));
		else if (r != msize) {
			log_error("%s (read): %d of %d bytes read", diag, r,
				msize);
			r = -1;
		} else
			*size = mdata.chunk_size;
		close(fd);
	}
#endif
	return (r);
}

static int
fs_open(const char *path, int flags, mode_t mode, size_t *chunk_size)
{
	int fd, r = 0;
	char *d;

	if ((flags & O_ACCMODE) == O_RDONLY) {
		if (get_chunk_size(path, chunk_size) == -1)
			return (-1);
	}
	fd = open(path, flags, mode);
	if (fd == -1 && ((flags & O_ACCMODE) != O_RDONLY)) {
		d = fs_dirname(path);
		if (d != NULL) {
			/* mkdir_p() may fail due to race condition */
			mkdir_p(d, 0755);
			free(d);
		}
		flags |= O_CREAT;
		fd = open(path, flags, mode);
	}
	if (fd == -1)
		return (fd);
	if (flags & O_CREAT) {
		r = set_chunk_size(path, *chunk_size);
		if (r == -1)
			close(fd);
	}
	return (r == -1 ? r : fd);
}

int
fs_inode_create(char *key, size_t key_size, int32_t uid, int32_t gid,
	mode_t mode, size_t chunk_size)
{
	char *p = key_to_path(key, key_size);
	int r = 0;

	log_debug("fs_inode_create: %s mode %o chunk_size %ld", p, mode,
		chunk_size);
	if (S_ISREG(mode)) {
		r = fs_open(p, O_CREAT|O_WRONLY|O_TRUNC, mode, &chunk_size);
		if (r == -1)
			return (r);
		close(r);
		r = 0;
	} else if (S_ISDIR(mode))
		r = mkdir_p(p, mode);
	return (r);
}

int
fs_inode_stat(char *key, size_t key_size, struct fs_stat *st)
{
	char *p = key_to_path(key, key_size);
	struct stat sb;
	int r;

	log_debug("fs_inode_stat: %s", p);
	r = stat(p, &sb);
	if (r == -1)
		goto err;

	if (S_ISREG(sb.st_mode)) {
		r = get_chunk_size(p, &st->chunk_size);
		if (r == -1)
			goto err;
	} else
		st->chunk_size = 0;

	st->mode = sb.st_mode;
	st->uid = sb.st_uid;
	st->gid = sb.st_gid;
	st->size = sb.st_size;
#ifndef USE_XATTR
	st->size -= msize;
#endif
	st->mtime = sb.st_mtim;
	st->ctime = sb.st_ctim;
	r = 0;
err:
	log_debug("fs_inode_stat: %d", r);
	return (r);
}

int
fs_inode_write(char *key, size_t key_size, const void *buf, size_t *size,
	off_t offset, mode_t mode, size_t chunk_size)
{
	char *p = key_to_path(key, key_size);
	size_t ss;
	int fd, r = 0;

	log_debug("fs_inode_write: %s size %ld offset %ld", p, *size, offset);
	ss = *size;
	if (ss + offset > chunk_size)
		ss = chunk_size - offset;
	if (ss <= 0) {
		*size = 0;
		goto err;
	}
	fd = r = fs_open(p, O_WRONLY, mode, &chunk_size);
	if (fd != -1) {
#ifndef USE_XATTR
		offset += msize;
#endif
		r = pwrite(fd, buf, ss, offset);
		close(fd);
	}
	if (r == -1)
		goto err;
	*size = r;
	r = 0;
err:
	log_debug("fs_inode_write: ret %d", r);
	return (r);
}

int
fs_inode_read(char *key, size_t key_size, void *buf, size_t *size,
	off_t offset)
{
	char *p = key_to_path(key, key_size);
	size_t ss, chunk_size;
	int fd, r;

	log_debug("fs_inode_read: %s size %ld offset %ld", p, *size, offset);
	fd = r = fs_open(p, O_RDONLY, 0644, &chunk_size);
	if (r == -1)
		goto err;
	log_debug("fs_inode_read: chunk_size %ld", chunk_size);

	ss = *size;
	if (ss + offset > chunk_size)
		ss = chunk_size - offset;
#ifndef USE_XATTR
	offset += msize;
#endif
	if (ss <= 0)
		r = 0;
	else
		r = pread(fd, buf, ss, offset);
	close(fd);
	if (r == -1)
		goto err;
	*size = r;
	r = 0;
err:
	log_debug("fs_inode_read: ret %d", r);
	return (r);
}

static char *
make_path(const char *dir, const char *entry)
{
	int dir_len, entry_len, slash = 1;
	char *p;

	if (dir == NULL || entry == NULL)
		return (NULL);

	dir_len = strlen(dir);
	entry_len = strlen(entry);

	if (dir_len > 0 && dir[dir_len - 1] == '/')
		slash = 0;
	p = malloc(dir_len + slash + entry_len + 1);
	if (p == NULL)
		return (NULL);
	strcpy(p, dir);
	if (slash)
		strcat(p, "/");
	strcat(p, entry);

	return (p);
}

static int
rmdir_r(const char *dir)
{
	DIR *d;
	struct dirent *dent;
	char *p;
	int r, save_errno;

	r = rmdir(dir);
	if (r == 0 || (errno != ENOTEMPTY && errno != EEXIST))
		return (r);

	d = opendir(dir);
	if (d == NULL)
		return (-1);

	while ((dent = readdir(d)) != NULL) {
		if (dent->d_name[0] == '.' && (dent->d_name[1] == '\0' ||
		    (dent->d_name[1] == '.' && dent->d_name[2] == '\0')))
			continue;

		p = make_path(dir, dent->d_name);
		if (p == NULL) {
			r = -1;
			errno = ENOMEM;
			break;
		}
		r = rmdir_r(p);
		free(p);
		if (r == -1)
			break;
	}
	save_errno = errno;
	closedir(d);
	errno = save_errno;
	if (r == 0)
		r = rmdir(dir);
	return (r);
}

int
fs_inode_remove(char *key, size_t key_size)
{
	char *p = key_to_path(key, key_size);
	struct stat sb;

	log_debug("fs_inode_remove: %s", p);
	if (stat(p, &sb) == -1)
		return (-1);
	if (S_ISREG(sb.st_mode))
		return (unlink(p));
	if (S_ISDIR(sb.st_mode))
		return (rmdir_r(p));
	return (-1);
}

int
fs_inode_readdir(char *path, void (*cb)(struct dirent *, void *),
	void *arg)
{
	char *p = key_to_path(path, strlen(path) + 1);
	struct dirent *dent;
	DIR *dp;
	int r;

	log_debug("fs_inode_readdir: %s", p);
	dp = opendir(p);
	if (dp != NULL) {
		r = 0;
		while ((dent = readdir(dp)) != NULL) {
			if (strchr(dent->d_name, ':'))
				continue;
			cb(dent, arg);
		}
		closedir(dp);
	} else
		r = -1;

	return (r);
}
