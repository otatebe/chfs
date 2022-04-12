#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <margo.h>
#ifdef USE_ABT_IO
#include <abt-io.h>
#endif

#include "path.h"
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

static int msize = sizeof(struct metadata);
#else
static int msize = 0;
#endif

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
		log_notice("fs_err: %s", strerror(-err));
		return (KV_ERR_UNKNOWN);
	}
}

void
fs_inode_init(char *dir, int niothreads)
{
	int r;

	r = chdir(dir);
	if (r == -1 && errno == ENOENT) {
		r = fs_mkdir_p(dir, 0755);
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
	while (*key == '/')
		++key;
	if (*key == '\0')
		key = ".";
	log_debug("%s: path %s", diag, key);
	return (key);
}

#define FS_XATTR_CHUNK_SIZE "user.chunk_size"
#define FS_XATTR_CACHE_FLAGS "user.cache_flags"

static int
set_metadata(const char *path, size_t size, int16_t flags)
{
	static const char diag[] = "set_metadata";
	int r;

#ifdef USE_XATTR
	r = setxattr(path, FS_XATTR_CHUNK_SIZE, &size, sizeof(size), 0);
	if (r == 0)
		r = setxattr(path, FS_XATTR_CACHE_FLAGS, &flags, sizeof(flags),
			0);
	if (r == -1) {
		r = -errno;
		log_error("%s (%s): %s", diag, path, strerror(errno));
	}
#else
	struct metadata mdata;
	int fd;

	fd = open(path, O_WRONLY, 0);
	if (fd == -1) {
		r = -errno;
		log_error("%s (%s): %s", diag, path, strerror(errno));
		return (r);
	}
	mdata.chunk_size = size;
	mdata.msize = msize;
	mdata.flags = flags;
	r = write(fd, &mdata, msize);
	if (r == -1) {
		r = -errno;
		log_error("%s (%s): %s", diag, path, strerror(errno));
	} else if (r != msize) {
		log_error("%s (%s): %d of %d bytes written", diag, path,
			r, msize);
		r = -ENOSPC;
	}
	close(fd);
#endif
	return (r);
}

static int
get_metadata(const char *path, size_t *size, int16_t *flags)
{
	static const char diag[] = "get_metadata";
	int r;

#ifdef USE_XATTR
	r = getxattr(path, FS_XATTR_CHUNK_SIZE, size, sizeof(*size));
	if (r > 0)
		r = getxattr(path, FS_XATTR_CACHE_FLAGS, flags, sizeof(*flags));
	if (r == -1) {
		r = -errno;
		log_info("%s (%s): %s", diag, path, strerror(errno));
	}
#else
	struct metadata mdata;
	struct stat sb;
	int fd;

	r = lstat(path, &sb);
	if (r == -1) {
		r = -errno;
		log_info("%s (%s): %s", diag, path, strerror(errno));
		return (r);
	} else if (!S_ISREG(sb.st_mode)) {
		log_info("%s (%s): not a regular file", diag, path);
		return (-EINVAL);
	}
	fd = open(path, O_RDONLY, 0);
	if (fd == -1) {
		r = -errno;
		log_info("%s (%s): %s", diag, path, strerror(errno));
		return (r);
	}
	r = read(fd, &mdata, msize);
	if (r == -1) {
		r = -errno;
		log_error("%s (%s): %s", diag, path, strerror(errno));
	} else if (r != msize) {
		log_error("%s (%s): %d of %d bytes read", diag, path, r, msize);
		r = -EIO;
	} else if (mdata.msize != msize) {
		log_error("%s (%s): metadata size mismatch", diag, path);
		r = -EIO;
	} else {
		*size = mdata.chunk_size;
		*flags = mdata.flags;
	}
	close(fd);
#endif
	return (r);
}

static int
fs_inode_dirty(int fd)
{
	static const char diag[] = "fs_inode_dirty";
	int r;

#ifdef USE_XATTR
	int16_t flags;

	r = fgetxattr(fd, FS_XATTR_CACHE_FLAGS, &flags, sizeof(flags));
	if (r > 0 && !(flags & CHFS_FS_DIRTY)) {
		flags |= CHFS_FS_DIRTY;
		r = fsetxattr(fd, FS_XATTR_CACHE_FLAGS, &flags, sizeof(flags),
			0);
	}
	if (r == -1) {
		r = -errno;
		log_error("%s (xattr): %s", diag, strerror(errno));
	}
#else
	struct metadata mdata;

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
#endif
	return (r);
}

static int
fs_open(const char *path, int flags, mode_t mode, size_t *chunk_size,
	int16_t *cache_flags, int *set_metadata_p)
{
	int fd, r = 0;

	if ((flags & O_ACCMODE) == O_RDONLY) {
		r = get_metadata(path, chunk_size, cache_flags);
		if (r < 0)
			return (r);
	}
	fd = open(path, flags, mode);
	if (fd == -1 && ((flags & O_ACCMODE) != O_RDONLY)) {
		fs_mkdir_parent(path);
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
	char *p, *key_save;
	mode_t mode = MODE_MASK(emode);
	int16_t flags = FLAGS_FROM_MODE(emode);
	int r, fd;
	static const char diag[] = "fs_inode_create";

	key_save = malloc(key_size);
	if (key_save == NULL)
		return (KV_ERR_NO_MEMORY);
	memcpy(key_save, key, key_size);

	p = key_to_path(key, key_size);
	log_debug("%s: %s mode %o chunk_size %ld", diag, p, mode, chunk_size);
	if (S_ISREG(mode)) {
		if (!(flags & CHFS_FS_CACHE))
			flags |= CHFS_FS_DIRTY;
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
		r = fs_mkdir_p(p, mode);
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
	else if (!(flags & CHFS_FS_CACHE))
		fs_inode_flush_enq(key_save, key_size);
	free(key_save);
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
	char *p, *key_save;
	mode_t mode = MODE_MASK(emode);
	int16_t flags = FLAGS_FROM_MODE(emode);
	size_t ss;
	int fd, r = 0, does_create;
	static const char diag[] = "fs_inode_write";

	key_save = malloc(key_size);
	if (key_save == NULL)
		return (KV_ERR_NO_MEMORY);
	memcpy(key_save, key, key_size);

	p = key_to_path(key, key_size);
	log_debug("%s: %s size %ld offset %ld flags %o", diag, p, *size,
		offset, flags);
	ss = *size;
	if (ss + offset > chunk_size) {
		if (offset >= chunk_size) {
			*size = 0;
			goto err;
		}
		ss = chunk_size - offset;
	}
	if (!(flags & CHFS_FS_CACHE))
		flags |= CHFS_FS_DIRTY;
	/* lock chunk */
	fd = r = fs_open(p, O_RDWR, mode, &chunk_size, &flags, &does_create);
	if (fd >= 0) {
		r = pwrite(fd, buf, ss, offset + msize);
		if (r == -1)
			r = -errno;
		else if (!does_create && !(flags & CHFS_FS_CACHE))
			r = fs_inode_dirty(fd);
		if (!(flags & CHFS_FS_CACHE))
			fs_inode_flush_enq(key_save, key_size);
		close(fd);
	}
	if (r >= 0)
		*size = r;
err:
	if (r < 0)
		log_error("%s: %s", diag, strerror(-r));
	else
		log_debug("%s: ret %d", diag, r);
	free(key_save);
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
	if (ss + offset > chunk_size) {
		if (offset >= chunk_size)
			ss = 0;
		else
			ss = chunk_size - offset;
	}
	if (ss == 0)
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
	char *p, *key_save;
	int r, fd;

	key_save = malloc(key_size);
	if (key_save == NULL)
		return (KV_ERR_NO_MEMORY);
	memcpy(key_save, key, key_size);

	p = key_to_path(key, key_size);
	log_debug("fs_inode_truncate: %s len %ld", p, len);
	r = truncate(p, len + msize);
	if (r == -1)
		r = -errno;
	else {
		fd = r = open(p, O_RDWR, 0);
		if (fd >= 0) {
			r = fs_inode_dirty(fd);
			fs_inode_flush_enq(key_save, key_size);
			close(fd);
		} else
			r = -errno;
	}
	free(key_save);
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
fs_inode_readdir(char *path, void (*cb)(struct dirent *, struct stat *, void *),
	void *arg)
{
	char *p = key_to_path(path, strlen(path) + 1), *pp;
	struct dirent *dent;
	DIR *dp;
	size_t size;
	int16_t flags;
	struct stat sb;
	int r, r2;

	log_debug("fs_inode_readdir: %s", p);
	dp = opendir(p);
	if (dp != NULL) {
		r = 0;
		while ((dent = readdir(dp)) != NULL) {
			if (strchr(dent->d_name, ':'))
				continue;
			pp = make_path(p, dent->d_name);
			if (pp != NULL) {
				r2 = get_metadata(pp, &size, &flags);
				free(pp);
				if (r2 > 0 && flags & CHFS_FS_CACHE)
					continue;
			}
			if (fstatat(dirfd(dp), dent->d_name, &sb,
				AT_SYMLINK_NOFOLLOW))
				continue;
			if (S_ISREG(sb.st_mode))
				sb.st_size -= msize;
			cb(dent, &sb, arg);
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

int
fs_inode_flush(void *key, size_t key_size)
{
	int index, keylen, r = KV_SUCCESS, src_fd, dst_fd, flags;
	size_t chunk_size;
	int16_t cache_flags;
	char *dst, *p, *buf, sym_buf[PATH_MAX];
	struct stat sb;
	static const char diag[] = "flush";

	keylen = strlen(key) + 1;
	if (keylen == key_size)
		index = 0;
	else
		index = atoi(key + keylen);
	log_debug("%s: key=%s, index=%d", diag, (char *)key, index);

	dst = path_backend(key);
	if (dst == NULL) {
		r = KV_ERR_NO_BACKEND_PATH;
		log_debug("%s: %s", diag, kv_err_string(r));
		return (r);
	}

	p = key_to_path(key, key_size);
	if (lstat(p, &sb) == -1) {
		r = fs_err(-errno);
		goto free_dst;
	}
	if (S_ISREG(sb.st_mode))
		goto regular_file;

	if (S_ISDIR(sb.st_mode)) {
		r = fs_mkdir_p(dst, sb.st_mode);
	} else if (S_ISLNK(sb.st_mode)) {
		r = readlink(p, sym_buf, sizeof sym_buf);
		if (r > 0) {
			sym_buf[r] = '\0';
			r = symlink(sym_buf, dst);
			if (r == -1) {
				fs_mkdir_parent(dst);
				r = symlink(sym_buf, dst);
			}
		}
	} else {
		r = KV_ERR_NOT_SUPPORTED;
		goto free_dst;
	}
	if (r == -1)
		r = fs_err(-errno);
	else
		r = KV_SUCCESS;
	goto free_dst;

regular_file:
	src_fd = r = fs_open(p, O_RDONLY, sb.st_mode, &chunk_size,
		&cache_flags, NULL);
	if (r < 0) {
		r = fs_err(r);
		goto free_dst;
	}
	if (!(cache_flags & CHFS_FS_DIRTY)) {
		log_debug("%s: clean", diag);
		r = KV_SUCCESS;
		goto close_src_fd;
	}

	buf = malloc(sb.st_size - msize);
	if (buf == NULL) {
		r = KV_ERR_NO_MEMORY;
		goto close_src_fd;
	}

	flags = O_WRONLY;
	if (!(cache_flags & CHFS_FS_CACHE))
		flags |= O_CREAT;

	if ((dst_fd = open(dst, flags, sb.st_mode)) == -1)
		r = fs_err(-errno);
	else {
		r = pread(src_fd, buf, sb.st_size - msize, msize);
		if (r == -1)
			r = fs_err(-errno);
		else if (r != sb.st_size - msize) {
			log_error("%s: %d of %ld bytes read", diag, r,
				sb.st_size - msize);
			r = KV_ERR_PARTIAL_READ;
		} else {
			r = pwrite(dst_fd, buf, r, index * chunk_size);
			if (r == -1)
				r = fs_err(-errno);
			else if (r != sb.st_size - msize) {
				log_error("%s: %d of %ld bytes written", diag,
					r, sb.st_size - msize);
				r = KV_ERR_PARTIAL_WRITE;
			} else if (r < chunk_size) {
				r = ftruncate(dst_fd, index * chunk_size + r);
				if (r == -1)
					r = fs_err(-errno);
			} else
				r = KV_SUCCESS;
		}
		close(dst_fd);
	}
close_src_fd:
	close(src_fd);
free_dst:
	free(dst);
	if (r == KV_SUCCESS && S_ISREG(sb.st_mode)) {
		r = set_metadata(p, chunk_size,
		    (cache_flags & ~CHFS_FS_DIRTY) | CHFS_FS_CACHE);
		r = fs_err(r);
	}
	if (r != KV_SUCCESS)
		log_error("%s: %s", diag, kv_err_string(r));
	return (r);
}
