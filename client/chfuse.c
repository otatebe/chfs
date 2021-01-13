#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stddef.h>
#include "chfs.h"

static void *
chfuse_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctx = fuse_get_context();
	const char *server = ctx->private_data;

	puts("init");
	chfs_init(server);
	return (NULL);
}

static int
chfuse_getattr(const char *path, struct stat *st)
{
	int ret;

	printf("getattr: %s\n", path);
	ret = chfs_stat(path, st);
	if (ret == -1)
		return (-ENOENT);
	/* FUSE requires at least 8 bytes for a directory */
	if (S_ISDIR(st->st_mode) && st->st_size < 8)
		st->st_size = 8;
	return (0);
}

static int
chfuse_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd, ret = 0;

	printf("create: %s\n", path);
	fd = chfs_create(path, fi->flags, mode);
	if (fd >= 0)
		fi->fh = fd;
	else
		ret = -EIO;

	return (ret);
}

static int
chfuse_open(const char *path, struct fuse_file_info *fi)
{
	int fd, ret = 0;

	printf("open: %s\n", path);
	fd = chfs_open(path, fi->flags);
	if (fd >= 0)
		fi->fh = fd;
	else
		ret = -EIO;

	return (ret);
}

static int
chfuse_release(const char *path, struct fuse_file_info *fi)
{
	int ret;

	printf("release: %s\n", path);
	ret = chfs_close(fi->fh);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_write(const char *path, const char *buf, size_t size,
       off_t offset, struct fuse_file_info *fi)
{
	ssize_t ret;

	printf("pwrite: path %s size %ld offset %ld\n", path, size, offset);
	ret = chfs_pwrite(fi->fh, buf, size, offset);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	ssize_t ret;

	printf("pread: path %s size %ld offset %ld\n", path, size, offset);
	ret = chfs_pread(fi->fh, buf, size, offset);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	int ret;

	printf("fsync: %s\n", path);
	ret = chfs_fsync(fi->fh);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_unlink(const char *path)
{
	int ret;

	printf("unlink: %s\n", path);
	ret = chfs_unlink(path);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_mkdir(const char *path, mode_t mode)
{
	int ret;

	printf("mkdir: %s\n", path);
	ret = chfs_mkdir(path, mode);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_rmdir(const char *path)
{
	int ret;

	printf("rmdir: %s\n", path);
	ret = chfs_rmdir(path);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static int
chfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	int ret;

	printf("readdir: %s\n", path);
	ret = chfs_readdir(path, buf, filler);
	if (ret == -1)
		return (-EIO);
	return (ret);
}

static const struct fuse_operations chfs_op = {
	.init		= chfuse_init,
	.getattr	= chfuse_getattr,
	.create		= chfuse_create,
	.open		= chfuse_open,
	.release	= chfuse_release,
	.write		= chfuse_write,
	.read		= chfuse_read,
	.fsync		= chfuse_fsync,
	.unlink		= chfuse_unlink,
	.mkdir		= chfuse_mkdir,
	.rmdir		= chfuse_rmdir,
	.readdir	= chfuse_readdir,
};

static struct options {
	const char *server;
	int usage;
} options;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--server=%s", server),
	OPTION("-h", usage),
	OPTION("--help", usage),
	FUSE_OPT_END
};

static void usage(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("file-system specific options:\n"
	       "    --server=<s>	server name\n"
	       "\n");
}

int
main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	options.server = NULL;
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return (1);

	if (options.usage) {
		usage(argv[0]);
		fuse_opt_add_arg(&args, "-ho");
	}

	ret = fuse_main(args.argc, args.argv, &chfs_op, (void *)options.server);
	fuse_opt_free_args(&args);
	return (ret);
}
