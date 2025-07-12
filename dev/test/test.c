#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
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

	_(chfs_term());
}
