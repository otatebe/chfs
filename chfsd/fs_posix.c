#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <margo.h>
#ifdef USE_ABT_IO
#include <abt-io.h>
#endif

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
	uint16_t msize;
	uint16_t flags;
};
#else
struct metadata {
	uint16_t msize;
	uint16_t flags;
};
#endif
static int msize = sizeof(struct metadata);

#ifdef USE_ABT_IO
static abt_io_instance_id abtio;
static __thread int __r;

#define open(path, flags, mode) \
	((__r = abt_io_open(abtio, path, flags, mode)) < 0 ? \
	 (errno = -__r), -1 : __r)
#define close(fd) abt_io_close(abtio, fd)
#define write(fd, buf, count) \
	((__r = abt_io_write(abtio, fd, buf, count)) < 0 ? \
	 (errno = -__r), -1 : __r)
#define read(fd, buf, count) \
	((__r = abt_io_read(abtio, fd, buf, count)) < 0 ? \
	 (errno = -__r), -1 : __r)
#define pwrite(fd, buf, count, off) \
	((__r = abt_io_pwrite(abtio, fd, buf, count, off)) < 0 ? \
	 (errno = -__r), -1 : __r)
#define pread(fd, buf, count, off) \
	((__r = abt_io_pread(abtio, fd, buf, count, off)) < 0 ? \
	 (errno = -__r), -1 : __r)
#ifdef HAVE_ABT_IO_TRUNCATE
#define truncate(path, len) \
	((__r = abt_io_truncate(abtio, path, len)) < 0 ? \
	 (errno = -__r), -1 : __r)
#endif
#define unlink(path) \
	((__r = abt_io_unlink(abtio, path)) < 0 ? (errno = -__r), -1 : __r)
#endif

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
		return (KV_ERR_UNKNOWN);
	}
}

void
fs_inode_init(char *dir, int niothreads)
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

#ifdef USE_ABT_IO
	abtio = abt_io_init(niothreads);
	if (abtio == ABT_IO_INSTANCE_NULL)
		log_fatal("abt_io_init failed, abort");
#endif
	log_info("fs_inode_init: path %s", dir);
}

/* key is modified */
static char *
key_to_path(char *key, size_t key_size)
{
	size_t klen = strlen(key);
	static const char diag[] = "key_to_path";

	log_debug("%s: key %s", diag, key);
	if (klen + 1 < key_size)
		key[klen] = ':';
	while (*key && *key == '/')
		++key;
	if (*key == '\0')
		key = ".";
	log_debug("%s: path %s", diag, key);
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
	if (r == NULL) {
		log_error("fs_dirname: no memory");
		return (NULL);
	}
	strncpy(r, path, p);
	r[p] = '\0';
	log_debug("fs_dirname: path %s dirname %s", path, r);
	return (r);
}

#define FS_XATTR_CHUNK_SIZE "user.chunk_size"

static int
set_metadata(const char *path, size_t size, int16_t flags)
{
	static const char diag[] = "set_metadata";
	struct metadata mdata;
	int fd, r;

	fd = open(path, O_WRONLY, 0);
	if (fd == -1) {
		r = -errno;
		log_error("%s: %s", diag, strerror(errno));
		return (r);
	}
#ifdef USE_XATTR
	r = setxattr(path, FS_XATTR_CHUNK_SIZE, &size, sizeof(size), 0);
	if (r == -1) {
		r = -errno;
		log_error("%s: %s", diag, strerror(errno));
		goto close_fd;
	}
#else
	mdata.chunk_size = size;
#endif
	mdata.msize = msize;
	mdata.flags = flags;
	r = write(fd, &mdata, msize);
	if (r == -1) {
		r = -errno;
		log_error("%s (write): %s", diag, strerror(errno));
	} else if (r != msize) {
		log_error("%s (write): %d of %d bytes written", diag,
			r, msize);
		r = -ENOSPC;
	}
#ifdef USE_XATTR
close_fd:
#endif
	close(fd);
	return (r);
}

static int
get_metadata(const char *path, size_t *size, int16_t *flags)
{
	static const char diag[] = "get_metadata";
	struct metadata mdata;
	int fd, r;

	fd = open(path, O_RDONLY, 0);
	if (fd == -1) {
		r = -errno;
		log_info("%s: %s", diag, strerror(errno));
		return (r);
	}
	r = read(fd, &mdata, msize);
	if (r == -1) {
		r = -errno;
		log_error("%s (read): %s", diag, strerror(errno));
	} else if (r != msize) {
		log_error("%s (read): %d of %d bytes read", diag, r, msize);
		r = -EIO;
	} else if (mdata.msize != msize) {
		log_error("%s: metadata size mismatch", diag);
		r = -EIO;
	} else {
#ifdef USE_XATTR
		r = getxattr(path, FS_XATTR_CHUNK_SIZE, size, sizeof(*size));
		if (r == -1) {
			r = -errno;
			log_info("%s: %s", diag, strerror(errno));
			goto close_fd;
		}
#else
		*size = mdata.chunk_size;
#endif
		*flags = mdata.flags;
	}
#ifdef USE_XATTR
close_fd:
#endif
	close(fd);
	return (r);
}

static int
fs_inode_dirty(int fd)
{
	static const char diag[] = "fs_inode_dirty";
	struct metadata mdata;
	int r;

	r = pread(fd, &mdata, msize, 0);
	if (r == -1) {
		r = -errno;
		log_error("%s (read): %s", diag, strerror(errno));
	} else if (r != msize) {
		log_error("%s (read): %d of %d bytes read", diag, r, msize);
		r = -EIO;
	} else if (mdata.msize != msize) {
		log_error("%s: metadata size mismatch", diag);
		r = -EIO;
	} else if ((mdata.flags & CHFS_FS_DIRTY) == 0) {
		mdata.flags |= CHFS_FS_DIRTY;
		r = pwrite(fd, &mdata, msize, 0);
		if (r == -1) {
			r = -errno;
			log_error("%s (write): %s", diag, strerror(errno));
		} else if (r != msize) {
			log_error("%s (write): %d of %d bytes written", diag,
				r, msize);
			r = -ENOSPC;
		}
	}
	return (r);
}

static int
fs_open(const char *path, int flags, mode_t mode, size_t *chunk_size,
	int16_t *cache_flags, int *set_metadata_p)
{
	int fd, r = 0;
	char *d;

	if ((flags & O_ACCMODE) == O_RDONLY) {
		r = get_metadata(path, chunk_size, cache_flags);
		if (r < 0)
			return (r);
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
		return (-errno);
	if (flags & O_CREAT) {
		r = set_metadata(path, *chunk_size, *cache_flags);
		if (r < 0)
			close(fd);
		else if (set_metadata_p)
			*set_metadata_p = 1;
	}
	return (r < 0 ? r : fd);
}

int
fs_inode_create(char *key, size_t key_size, uint32_t uid, uint32_t gid,
	uint32_t emode, size_t chunk_size, const void *buf, size_t size)
{
	char *p = key_to_path(key, key_size);
	mode_t mode = MODE_MASK(emode);
	int16_t flags = FLAGS_FROM_MODE(emode);
	int r, fd;
	static const char diag[] = "fs_inode_create";

	log_debug("%s: %s mode %o chunk_size %ld", diag, p, mode, chunk_size);
	if (S_ISREG(mode)) {
		fd = r = fs_open(p, O_CREAT|O_WRONLY|O_TRUNC, mode, &chunk_size,
			&flags, NULL);
		if (fd >= 0) {
			if (buf && size > 0) {
				if (size > chunk_size)
					size = chunk_size;
				r = pwrite(fd, buf, size, msize);
				if (r == -1)
					r = -errno;
			}
			close(fd);
		}
	} else if (S_ISDIR(mode)) {
		r = mkdir_p(p, mode);
		if (r == -1)
			r = -errno;
	} else if (S_ISLNK(mode)) {
		r = symlink(buf, p);
		if (r == -1)
			r = -errno;
	} else
		r = -ENOTSUP;
	if (r < 0)
		log_error("%s: %s", diag, strerror(-r));

	return (fs_err(r));
}

int
fs_inode_create_stat(char *key, size_t key_size, struct fs_stat *st,
	const void *buf, size_t size)
{
	char *p = key_to_path(key, key_size);
	struct timespec times[2];
	mode_t mode = MODE_MASK(st->mode);
	int16_t flags = 0;
	int r, fd;
	static const char diag[] = "fs_inode_create_stat";

	log_debug("%s: %s mode %o chunk_size %ld", diag, p, mode,
		st->chunk_size);
	if (S_ISREG(mode)) {
		fd = r = fs_open(p, O_CREAT|O_WRONLY|O_TRUNC, mode,
			&st->chunk_size, &flags, NULL);
		if (fd >= 0) {
			if (buf && size > 0) {
				if (size > st->chunk_size + msize)
					size = st->chunk_size + msize;
				r = pwrite(fd, buf, size, 0);
				if (r == -1)
					r = -errno;
			}
			close(fd);
		}
	} else
		r = fs_inode_create(key, key_size, st->uid, st->gid, st->mode,
			st->chunk_size, buf, size);
	if (r == KV_SUCCESS) {
		times[0] = times[1] = st->mtime;
		utimensat(AT_FDCWD, p, times, AT_SYMLINK_NOFOLLOW);
	}
	return (r);
}

int
fs_inode_stat(char *key, size_t key_size, struct fs_stat *st)
{
	char *p = key_to_path(key, key_size);
	struct stat sb;
	int r;
	int16_t flags;
	static const char diag[] = "fs_inode_stat";

	log_debug("%s: %s", diag, p);
	r = lstat(p, &sb);
	if (r == -1) {
		r = -errno;
		goto err;
	}
	if (S_ISREG(sb.st_mode)) {
		r = get_metadata(p, &st->chunk_size, &flags);
		if (r < 0)
			goto err;
	} else
		st->chunk_size = 0;

	st->mode = MODE_FLAGS(sb.st_mode, flags);
	st->uid = sb.st_uid;
	st->gid = sb.st_gid;
	st->size = sb.st_size;
	if (S_ISREG(sb.st_mode))
		st->size -= msize;
	st->mtime = sb.st_mtim;
	st->ctime = sb.st_ctim;
err:
	log_debug("%s: %d", diag, r);
	return (fs_err(r));
}

int
fs_inode_write(char *key, size_t key_size, const void *buf, size_t *size,
	off_t offset, uint32_t emode, size_t chunk_size)
{
	char *p = key_to_path(key, key_size);
	mode_t mode = MODE_MASK(emode);
	int16_t flags = FLAGS_FROM_MODE(emode);
	size_t ss;
	int fd, r = 0, does_create;
	static const char diag[] = "fs_inode_write";

	log_debug("%s: %s size %ld offset %ld", diag, p, *size, offset);
	ss = *size;
	if (ss + offset > chunk_size)
		ss = chunk_size - offset;
	if (ss <= 0) {
		*size = 0;
		goto err;
	}
	if (flags & CHFS_FS_NEW)
		flags |= CHFS_FS_DIRTY;
	fd = r = fs_open(p, O_RDWR, mode, &chunk_size, &flags, &does_create);
	if (fd >= 0) {
		r = pwrite(fd, buf, ss, offset + msize);
		if (r == -1)
			r = -errno;
		else if (!does_create && flags & CHFS_FS_NEW)
			r = fs_inode_dirty(fd);
		close(fd);
	}
	if (r < 0)
		goto err;
	*size = r;
err:
	if (r < 0)
		log_error("%s: %s", diag, strerror(-r));
	else
		log_debug("%s: ret %d", diag, r);
	return (fs_err(r));
}

int
fs_inode_read(char *key, size_t key_size, void *buf, size_t *size,
	off_t offset)
{
	char *p = key_to_path(key, key_size);
	struct stat sb;
	size_t ss, chunk_size;
	int16_t flags = 0;
	int fd, r;
	static const char diag[] = "fs_inode_read";

	log_debug("%s: %s size %ld offset %ld", diag, p, *size, offset);
	if (lstat(p, &sb) == 0 && S_ISLNK(sb.st_mode)) {
		r = readlink(p, buf, *size);
		if (r == -1)
			r = -errno;
		else
			*size = r;
		goto done;
	}
	fd = r = fs_open(p, O_RDONLY, 0644, &chunk_size, &flags, NULL);
	if (r < 0)
		goto done;
	log_debug("%s: chunk_size %ld", diag, chunk_size);

	ss = *size;
	if (ss + offset > chunk_size)
		ss = chunk_size - offset;
	if (ss <= 0)
		r = 0;
	else {
		r = pread(fd, buf, ss, offset + msize);
		if (r == -1)
			r = -errno;
	}
	close(fd);
	if (r < 0)
		goto done;
	*size = r;
done:
	log_debug("%s: ret %d", diag, r);
	return (fs_err(r));
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
fs_inode_truncate(char *key, size_t key_size, off_t len)
{
	char *p = key_to_path(key, key_size);
	int r, fd;

	log_debug("fs_inode_truncate: %s len %ld", p, len);
	r = truncate(p, len + msize);
	if (r == -1)
		r = -errno;
	else {
		fd = r = open(p, O_RDWR);
		if (fd >= 0) {
			r = fs_inode_dirty(fd);
			close(fd);
		} else
			r = -errno;
	}
	return (fs_err(r));
}

int
fs_inode_remove(char *key, size_t key_size)
{
	char *p = key_to_path(key, key_size);
	struct stat sb;
	int r;

	log_debug("fs_inode_remove: %s", p);
	if (lstat(p, &sb) == -1)
		return (fs_err(-errno));

	if (S_ISDIR(sb.st_mode))
		r = rmdir_r(p);
	else
		r = unlink(p);
	if (r == -1)
		r = -errno;
	return (fs_err(r));
}

int
fs_inode_readdir(char *path, void (*cb)(struct dirent *, void *),
	void *arg)
{
	char *p = key_to_path(path, strlen(path) + 1);
	struct dirent *dent;
	DIR *dp;
	size_t size;
	int16_t flags;
	int r, r2;

	log_debug("fs_inode_readdir: %s", p);
	dp = opendir(p);
	if (dp != NULL) {
		r = 0;
		while ((dent = readdir(dp)) != NULL) {
			if (strchr(dent->d_name, ':'))
				continue;
			r2 = get_metadata(dent->d_name, &size, &flags);
			if (r2 < 0 || !(flags & CHFS_FS_NEW))
				continue;
			cb(dent, arg);
		}
		closedir(dp);
	} else
		r = -errno;

	return (fs_err(r));
}

static char *
fs_basename(char *p)
{
	int len;

	if (p == NULL || (len = strlen(p)) == 0)
		return (NULL);
	while (len > 0 && p[len - 1] != '/')
		--len;
	return (&p[len]);
}

int
fs_inode_unlink_chunk_all(char *path)
{
	char *d, *b, p[PATH_MAX];
	DIR *dp;
	struct dirent *de;
	int len, plen = 0;

	b = fs_basename(path);
	if (b == NULL || b[0] == '\0')
		return (0);
	len = strlen(b);

	d = fs_dirname(path);
	dp = opendir(d != NULL ? d : ".");
	if (dp == NULL) {
		free(d);
		return (fs_err(-errno));
	}
	if (d != NULL) {
		strcpy(p, d);
		plen = strlen(p);
		p[plen++] = '/';
		p[plen] = '\0';
	}
	while ((de = readdir(dp)) != NULL) {
		if (de->d_name[0] == '.' && (de->d_name[1] == '\0' ||
			(de->d_name[1] == '.' && de->d_name[2] == '\0')))
			continue;
		if (strncmp(de->d_name, b, len) == 0 &&
			(de->d_name[len] == ':' || de->d_name[len] == '\0')) {
			if (d != NULL) {
				strcpy(&p[plen], de->d_name);
				unlink(p);
			} else
				unlink(de->d_name);
		}
	}
	closedir(dp);
	free(d);
	return (0);
}
