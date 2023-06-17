#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "timespec.h"
#include "file.h"
#include "kv_err.h"
#include "fs_err.h"
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
