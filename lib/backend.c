#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <margo.h>
#include <mercury_proc_string.h>
#include "timespec.h"
#include "path.h"
#include "file.h"
#include "kv_err.h"
#include "kv_types.h"
#include "fs_types.h"
#include "fs_err.h"
#include "key.h"
#include "log.h"

int
backend_write(char *dst, int flags, mode_t mode,
	const char *buf, size_t size, off_t off)
{
	struct timespec ts1, ts2, ts3, ts4, ts5, ts6, ts7, ts8;
	int fd, r;
	static const char diag[] = "backend_write";

	clock_gettime(CLOCK_REALTIME, &ts1);
	fd = open(dst, flags, mode);
	if (fd == -1) {
		fs_mkdir_parent(dst);
		fd = open(dst, flags, mode);
	}
	clock_gettime(CLOCK_REALTIME, &ts2);
	if (fd == -1)
		r = fs_err(-errno, diag);
	else {
		r = pwrite(fd, buf, size, off);
		if (r == -1)
			r = fs_err(-errno, diag);
		else if (r != size) {
			log_info("%s: %s: %d of %ld bytes written", diag,
				dst, r, size);
			r = KV_ERR_PARTIAL_WRITE;
		} else
			r = KV_SUCCESS;
		clock_gettime(CLOCK_REALTIME, &ts3);
		close(fd);
	}
	clock_gettime(CLOCK_REALTIME, &ts4);

	timespec_sub(&ts1, &ts4, &ts5);
	if (r == KV_SUCCESS && S_ISREG(mode) && ts5.tv_sec > 0) {
		timespec_sub(&ts1, &ts2, &ts6);
		timespec_sub(&ts2, &ts3, &ts7);
		timespec_sub(&ts3, &ts4, &ts8);
		log_notice("%s: %s size %ld off %ld flush %ld.%09ld sec "
			"(open %ld.%09ld sec, write %ld.%09ld sec, "
			"close %ld.%09ld sec)", diag, dst, size, off,
			ts5.tv_sec, ts5.tv_nsec, ts6.tv_sec, ts6.tv_nsec,
			ts7.tv_sec, ts7.tv_nsec, ts8.tv_sec, ts8.tv_nsec);
	} else if (ts5.tv_sec > 0)
		log_notice("%s: %s size %ld off %ld flush %ld.%09ld sec", diag,
			dst, size, off, ts5.tv_sec, ts5.tv_nsec);

	return (r);
}

int
backend_write_key(const char *key, mode_t mode,
	const char *buf, size_t size, off_t off)
{
	char *dst;
	int r;
	static const char diag[] = "backend_write_key";

	dst = path_backend(key);
	if (dst == NULL) {
		r = KV_ERR_NO_BACKEND_PATH;
		log_debug("%s: %s", diag, kv_err_string(r));
		return (r);
	}
	r = backend_write(dst, O_WRONLY|O_CREAT, mode, buf, size, off);
	free(dst);
	return (r);
}

char *
backend_read(char *path, size_t psize, size_t chunk_size,
	struct fs_stat *st, size_t *size)
{
	char *buf = malloc(chunk_size), *bp;
	struct stat sb;
	int s, r;
	size_t rr = 0;
	int index = key_index(path, psize);
	off_t offset = index * chunk_size;

	if (buf == NULL)
		return (NULL);
	if ((bp = path_backend(path)) == NULL)
		goto err_free_buf;
	if (stat(bp, &sb) || (s = open(bp, O_RDONLY)) == -1) {
		free(bp);
		goto err_free_buf;
	}
	free(bp);
	r = pread(s, buf, chunk_size, offset);
	while (r > 0) {
		rr += r;
		r = pread(s, buf + rr, chunk_size - rr, offset + rr);
	}
	close(s);
	if (r < 0 || rr == 0)
		goto err_free_buf;

	if (st) {
		st->mode = sb.st_mode;
		st->uid = sb.st_uid;
		st->gid = sb.st_gid;
		st->size = sb.st_size;
		st->chunk_size = chunk_size;
		st->mtime = sb.st_mtim;
		st->ctime = sb.st_ctim;
	}
	if (size)
		*size = rr;
	return (buf);

err_free_buf:
	free(buf);
	return (NULL);
}
