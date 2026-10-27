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

#define _(p) assert((p) == 0)

static char *
alloc_buf(int size)
{
	char *b = malloc(size);
	int i;

	assert(b);
	srandom(size);
	for (i = 0; i < size; ++i)
		b[i] = random() % 256;

	return (b);
}

static void
test_create_file(char *f, int chunk_size, int size, int blk_size)
{
	int fd, r, i;
	char *b1, *b2;
	struct stat sb;

	if (blk_size <= 0)
		blk_size = size;

	fd = chfs_create_chunk_size(f, O_WRONLY, 0644, chunk_size);
	assert(fd != -1);

	b1 = alloc_buf(size);
	i = 0;
	r = size - i;
	if (r > blk_size)
		r = blk_size;
	while (i < size) {
		assert(chfs_write(fd, &b1[i], r) == r);
		i += r;
		r = size - i;
		if (r > blk_size)
			r = blk_size;
	}

	b2 = malloc(size);
	assert(b2);
	i = 0;
	r = size - i;
	if (r > blk_size)
		r = blk_size;
	while (i < size) {
		assert(chfs_pread(fd, &b2[i], r, i) == r);
		i += r;
		r = size - i;
		if (r > blk_size)
			r = blk_size;
	}

	for (i = 0; i < size; ++i)
		assert(b1[i] == b2[i]);

	free(b1);
	free(b2);

	_(chfs_fsync(fd));
	_(chfs_close(fd));

	_(chfs_stat(f, &sb));
	assert(sb.st_blksize == chunk_size);
	assert(sb.st_size == size);
	_(chfs_access(f, F_OK));
}

static void
test_unlink(char *f)
{
	struct stat sb;

	_(chfs_unlink(f));
	assert(chfs_stat(f, &sb));
	assert(chfs_access(f, F_OK));
}

static void
test_mkdir(char *p)
{
	struct stat sb;

	_(chfs_mkdir(p, 0755));
	_(chfs_stat(p, &sb));
	assert(S_ISDIR(sb.st_mode));
	_(chfs_access(p, F_OK));
}

static void
test_rmdir(char *d)
{
	struct stat sb;

	_(chfs_rmdir(d));
	assert(chfs_stat(d, &sb));
	assert(chfs_access(d, F_OK));
}

static void
test_write_read(char *f, int chunk_size, int size, int blk_size)
{
	printf("test_write_read: %s chunk %d size %d blk %d: ", f, chunk_size,
			size, blk_size);
	fflush(stdout);
	test_create_file(f, chunk_size, size, blk_size);

	test_unlink(f);
	puts("done");
}

static void
test_truncate(char *f, int chunk_size, int size)
{
	int fd;
	char buf[1];
	struct stat sb;

	printf("test_truncate: %s chunk %d size %d: ", f, chunk_size, size);
	fflush(stdout);
	test_create_file(f, chunk_size, size, 0);

	_(chfs_truncate(f, 0));
	_(chfs_stat(f, &sb));
	assert(sb.st_size == 0);

	fd = chfs_open(f, O_RDONLY);
	assert(fd != -1);
	_(chfs_pread(fd, buf, 1, 0));
	_(chfs_close(fd));

	test_unlink(f);
	puts("done");
}

static void
test_ftruncate(char *f, int chunk_size, int size)
{
	int fd;
	char buf[1];
	struct stat sb;

	printf("test_ftruncate: %s chunk %d size %d: ", f, chunk_size, size);
	fflush(stdout);
	test_create_file(f, chunk_size, size, 0);

	fd = chfs_open(f, O_RDWR);
	assert(fd != -1);
	_(chfs_ftruncate(fd, 0));
	_(chfs_fstat(fd, &sb));
	assert(sb.st_size == 0);

	_(chfs_pread(fd, buf, 1, 0));
	_(chfs_close(fd));

	test_unlink(f);
	puts("done");
}

static void
test_symlink(char *p1, char *p2)
{
	struct stat sb;
	int r, len = strlen(p1);
	char *b = malloc(len);

	assert(b);
	printf("test_symlink: %s %s: ", p1, p2);
	fflush(stdout);
	_(chfs_symlink(p1, p2));
	_(chfs_lstat(p2, &sb));
	assert(S_ISLNK(sb.st_mode));

	r = chfs_readlink(p2, b, len);
	assert(r == len);
	assert(strncmp(p1, b, len) == 0);

	free(b);
	test_unlink(p2);
	puts("done");
}

static int count = 0;

static int
filler(void *b, const char *e, const struct stat *st, off_t o)
{
	if (e[0] == '.' && (e[1] == '\0' || (e[1] == '.' && e[2] == '\0')))
		return (0);
	++count;
	return (0);
}

static void
test_readdir(char *d)
{
	int len = strlen(d);
	char *b = malloc(len + 3);

	assert(b);
	printf("test_readdir: %s: ", d);
	fflush(stdout);

	test_mkdir(d);
	sprintf(b, "%s/a", d);
	test_create_file(b, 64, 256, 0);
	sprintf(b, "%s/b", d);
	test_create_file(b, 64, 256, 0);
	sprintf(b, "%s/c", d);
	test_create_file(b, 64, 256, 0);

	_(chfs_readdir(d, NULL, filler));
	assert(count == 3);
	count = 0;

	sprintf(b, "%s/a", d);
	test_unlink(b);
	sprintf(b, "%s/b", d);
	test_unlink(b);
	sprintf(b, "%s/c", d);
	test_unlink(b);
	test_rmdir(d);

	free(b);
	puts("done");
}

static void
test_bad_fd(char *f)
{
	int fd;

	printf("test_bad_fd: %s: ", f);
	fflush(stdout);
	fd = chfs_create(f, O_WRONLY, 0644);
	assert(fd != -1);
	_(chfs_close(fd));

	errno = 0;
	assert(chfs_close(fd) == -1 && errno == EBADF);
	errno = 0;
	assert(chfs_fsync(fd) == -1 && errno == EBADF);
	errno = 0;
	assert(chfs_close(-1) == -1 && errno == EBADF);

	test_unlink(f);
	puts("done");
}

/* buffered data should be visible before close */
static void
test_buffered_write(char *f, int chunk_size)
{
	int fd;
	char buf[256];
	struct stat sb;

	printf("test_buffered_write: %s chunk %d: ", f, chunk_size);
	fflush(stdout);
	fd = chfs_create_chunk_size(f, O_RDWR, 0644, chunk_size);
	assert(fd != -1);

	/* large read after a buffered write */
	assert(chfs_write(fd, "hello", 5) == 5);
	assert(chfs_pread(fd, buf, sizeof buf, 0) == 5);
	assert(memcmp(buf, "hello", 5) == 0);

	/* fstat after a buffered write */
	assert(chfs_write(fd, "world", 5) == 5);
	_(chfs_fstat(fd, &sb));
	assert(sb.st_size == 10);

	/* lseek(SEEK_END) after a buffered write */
	assert(chfs_pwrite(fd, "!", 1, 10) == 1);
	assert(chfs_seek(fd, 0, SEEK_END) == 11);

	/* ftruncate after a buffered write */
	assert(chfs_pwrite(fd, "abc", 3, 11) == 3);
	_(chfs_ftruncate(fd, 0));
	_(chfs_close(fd));
	_(chfs_stat(f, &sb));
	assert(sb.st_size == 0);

	test_unlink(f);
	puts("done");
}

#define MANY_FDS	250	/* the initial fd table size is 100 */

/* open many files to expand the fd table */
static void
test_many_fds(char *d)
{
	char b[64], c[16];
	int fds[MANY_FDS], i, n;

	printf("test_many_fds: %s %d: ", d, MANY_FDS);
	fflush(stdout);
	test_mkdir(d);
	for (i = 0; i < MANY_FDS; ++i) {
		sprintf(b, "%s/f%d", d, i);
		fds[i] = chfs_create(b, O_RDWR, 0644);
		assert(fds[i] != -1);
		n = sprintf(c, "%d", i);
		assert(chfs_write(fds[i], c, n) == n);
	}
	/* buffered data of the first fd is still accessible */
	assert(chfs_pread(fds[0], c, sizeof c, 0) == 1 && c[0] == '0');
	for (i = 0; i < MANY_FDS; ++i)
		_(chfs_close(fds[i]));

	for (i = 0; i < MANY_FDS; ++i) {
		sprintf(b, "%s/f%d", d, i);
		fds[i] = chfs_open(b, O_RDONLY);
		assert(fds[i] != -1);
		n = chfs_pread(fds[i], c, sizeof c - 1, 0);
		assert(n > 0);
		c[n] = '\0';
		assert(atoi(c) == i);
		_(chfs_close(fds[i]));
		test_unlink(b);
	}
	test_rmdir(d);
	puts("done");
}

struct linux_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

#define GETDENTS_NFILES	100

/* the directory listing is larger than the getdents buffer */
static void
test_getdents(char *d)
{
	char b[256], seen[GETDENTS_NFILES];
	struct linux_dirent64 *e;
	int fd, i, n, pos, nfiles = 0;

	printf("test_getdents: %s: ", d);
	fflush(stdout);
	test_mkdir(d);
	for (i = 0; i < GETDENTS_NFILES; ++i) {
		sprintf(b, "%s/f%d", d, i);
		fd = chfs_create(b, O_WRONLY, 0644);
		assert(fd != -1);
		_(chfs_close(fd));
	}
	memset(seen, 0, sizeof seen);

	fd = chfs_open(d, O_RDONLY | O_DIRECTORY);
	assert(fd != -1);
	errno = 0;
	assert(chfs_linux_getdents64(fd, b, 8) == -1 && errno == EINVAL);
	while ((n = chfs_linux_getdents64(fd, b, sizeof b)) > 0) {
		for (pos = 0; pos < n; pos += e->d_reclen) {
			e = (struct linux_dirent64 *)&b[pos];
			if (e->d_name[0] == '.')
				continue;
			assert(e->d_name[0] == 'f');
			i = atoi(&e->d_name[1]);
			assert(i >= 0 && i < GETDENTS_NFILES && !seen[i]);
			seen[i] = 1;
			++nfiles;
		}
	}
	assert(n == 0);
	assert(nfiles == GETDENTS_NFILES);
	_(chfs_close(fd));

	for (i = 0; i < GETDENTS_NFILES; ++i) {
		sprintf(b, "%s/f%d", d, i);
		test_unlink(b);
	}
	test_rmdir(d);
	puts("done");
}

int
main(int argc, char *argv[])
{

	_(chfs_init(NULL));

	printf("CHFS version %s\n", chfs_version());
	printf("CHFS size = %d\n", chfs_size());

	test_write_read("a", 64, 256, 0);
	test_write_read("a", 64, 257, 0);
	test_write_read("a", 64, 255, 0);

	chfs_set_async_access(1);
	puts("async access");
	test_write_read("a", 64, 256, 0);
	test_write_read("a", 64, 257, 0);
	test_write_read("a", 64, 255, 0);
	chfs_set_async_access(0);
	puts("sync access");

	chfs_set_buf_size(32);
	puts("buf size: 32");
	test_write_read("a", 64, 256, 1);
	chfs_set_buf_size(128);
	puts("buf size: 128");
	test_write_read("a", 64, 256, 1);
	test_write_read("a", 64, 257, 1);
	test_write_read("a", 64, 255, 1);
	chfs_set_buf_size(0);
	puts("buf size: 0");

	test_truncate("a", 64, 256);
	test_ftruncate("a", 64, 256);
	test_symlink("b", "a");
	test_readdir("a");
	test_bad_fd("a");
	test_buffered_write("a", 64);
	test_getdents("a");
	test_many_fds("a");

	_(chfs_term());
}
