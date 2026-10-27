#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <chfs.h>

/*
 * usage: flush_error command
 *
 * Writes buffered data, executes command that stops all CHFS servers,
 * and checks that the write-back errors are reported.
 */

#define CHUNK_SIZE	4096

static int
open_and_write(char *f, int size)
{
	char buf[CHUNK_SIZE];
	int fd;

	fd = chfs_create_chunk_size(f, O_WRONLY, 0644, CHUNK_SIZE);
	assert(fd != -1);
	memset(buf, 'x', sizeof buf);
	assert(chfs_write(fd, buf, size) == size);
	return (fd);
}

int
main(int argc, char *argv[])
{
	char buf[CHUNK_SIZE];
	int fd1, fd2, fd3, r, err, fail = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: flush_error command\n");
		return (2);
	}
	setenv("CHFS_RPC_TIMEOUT_MSEC", "1000", 1);
	assert(chfs_init(NULL) == 0);

	/* data smaller than the buffer size stay in the buffer */
	fd1 = open_and_write("flush-error-1", 10);
	fd2 = open_and_write("flush-error-2", 10);
	fd3 = open_and_write("flush-error-3", 10);

	if (system(argv[1]) != 0) {
		fprintf(stderr, "%s: failed\n", argv[1]);
		return (2);
	}

#define CHECK(label, expr, expect_fail) do { \
	errno = 0; \
	r = (expr); \
	err = errno; \
	printf("%-18s returns %d: %s\n", label, r, strerror(err)); \
	if ((r == -1) != (expect_fail)) \
		fail = 1; \
} while (0)

	/* the write-back error is reported once by fsync */
	CHECK("fsync(fd1)", chfs_fsync(fd1), 1);
	CHECK("close(fd1)", chfs_close(fd1), 0);
	/* close reports the write-back error */
	CHECK("close(fd2)", chfs_close(fd2), 1);
	/* write reports the error when it flushes the full buffer */
	memset(buf, 'x', sizeof buf);
	CHECK("write(fd3)", (int)chfs_write(fd3, buf, sizeof buf), 1);

	puts(fail ? "FAIL" : "OK");
	/* chfs_term() is not called since there are no servers */
	return (fail);
}
