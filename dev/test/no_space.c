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
 * usage: no_space chunk_size async dirty command
 *
 * Executes command that fills the scratch directory of a server, writes
 * a file, and checks that the file can be read via CHFS.  When there is
 * no space, the data is written to the backend.  When dirty is 1, the
 * first half of each chunk is written before the command.
 */

#define NCHUNK	32

int
main(int argc, char *argv[])
{
	char *buf, *rbuf;
	int fd, chunk_size, async, dirty, i, half;
	size_t size;
	ssize_t r, n;

	if (argc != 5) {
		fprintf(stderr, "usage: no_space chunk_size async dirty "
			"command\n");
		return (2);
	}
	chunk_size = atoi(argv[1]);
	async = atoi(argv[2]);
	dirty = atoi(argv[3]);
	half = chunk_size / 2;
	size = (size_t)chunk_size * NCHUNK;
	buf = malloc(size);
	rbuf = malloc(size);
	if (buf == NULL || rbuf == NULL)
		return (2);
	for (i = 0; i < NCHUNK * 2; ++i)
		memset(buf + (size_t)i * half, i + 1, half);

	if (chfs_init(NULL))
		return (2);
	chfs_set_async_access(async);
	printf("chunk_size %d async %d dirty %d: ", chunk_size, async, dirty);
	fflush(stdout);
	fd = chfs_create_chunk_size("no-space-test", O_RDWR, 0644, chunk_size);
	if (fd < 0) {
		perror("chfs_create");
		return (2);
	}
	if (dirty)
		for (i = 0; i < NCHUNK; ++i)
			if (chfs_pwrite(fd, buf + (size_t)i * chunk_size, half,
				(off_t)i * chunk_size) != half) {
				perror("chfs_pwrite");
				return (2);
			}
	if (system(argv[4]) != 0) {
		fprintf(stderr, "%s: failed\n", argv[4]);
		return (2);
	}
	if (dirty) {
		for (i = 0; i < NCHUNK; ++i)
			if (chfs_pwrite(fd, buf + (size_t)i * chunk_size + half,
				half, (off_t)i * chunk_size + half) != half) {
				perror("chfs_pwrite");
				return (1);
			}
	} else {
		for (n = 0; n < size; n += r) {
			r = chfs_pwrite(fd, buf + n, size - n, n);
			if (r <= 0) {
				perror("chfs_pwrite");
				return (1);
			}
		}
	}
	for (n = 0; n < size; n += r) {
		r = chfs_pread(fd, rbuf + n, size - n, n);
		if (r <= 0)
			break;
	}
	if (n != size || memcmp(buf, rbuf, size) != 0) {
		printf("%ld of %ld bytes read, MISMATCH\n", (long)n,
			(long)size);
		return (1);
	}
	puts("OK");
	chfs_close(fd);
	free(buf);
	free(rbuf);
	return (0);
}
