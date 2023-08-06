#include <unistd.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <margo.h>
#include "ring_types.h"
#include "kv_types.h"
#include "fs_types.h"
#include "fs.h"
#include "fs_kv.h"
#include "kv_err.h"
#include "kv.h"
#include "log.h"

static void
print_time(struct timespec *ts)
{
	char s[64];
	time_t t = ts->tv_sec;
	struct tm *tm = localtime(&t);

	strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", tm);
	printf("%s.%09ld", s, ts->tv_nsec);
	strftime(s, sizeof(s), "%z", tm);
	printf(" %s", s);
}

static void
print_stat(struct inode *ino)
{
	printf("  Mode: (%o) Uid: (%d) Gid: (%d) Size: %ld Chunk size: %ld "
		"flag: %d\n", ino->mode, ino->uid, ino->gid, ino->size,
		ino->chunk_size, ino->flags);
	printf("Modify: ");
	print_time(&ino->mtime);
	printf("\nChange: ");
	print_time(&ino->ctime);
	printf("\n");
}

static int opt_stat = 0;
static long opt_len = 0;

static void
print_data(const char *v, size_t vs)
{
	long i, len;
	struct inode *inode = (struct inode *)v;

	v += fs_msize;
	len = vs - fs_msize;
	if (len > inode->size)
		len = inode->size;
	if (len > opt_len)
		len = opt_len;
	for (i = 0; i < len; ++i)
		printf("%c", v[i]);
	printf("\n");
}

static int
get_all_cb(const char *k, size_t ks, const char *v, size_t vs, void *a)
{
	int i;

	printf("   Key: ");
	for (i = 0; i < ks; ++i)
		printf("%c", k[i] == '\0' ? '_' : k[i]);
	printf(" Value size: %ld\n", vs);

	if (opt_stat) {
		print_stat((struct inode *)v);
		if (opt_len > 0)
			print_data(v, vs);
		printf("\n");
	}
        return (0);
}

void
usage(char *prog_name)
{
	fprintf(stderr, "Usage: %s [-s] [-l #char] kv.db ...\n", prog_name);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int c, err;
	char *prog_name;

	prog_name = basename(argv[0]);

	while ((c = getopt(argc, argv, "l:s")) != -1) {
		switch (c) {
		case 'l':
			opt_len = atol(optarg);
			break;
		case 's':
			opt_stat = 1;
			break;
		default:
			usage(prog_name);
		}
	}
	argc -= optind;
	argv += optind;

	while (*argv) {
		printf("%s\n", *argv);
		kv_init(*argv, "cmap", "kv.db", 256 * 1024 * 1024);
		err = kv_get_all_cb(get_all_cb, NULL);
		if (err != KV_SUCCESS)
			log_error("%s", kv_err_string(err));
		kv_term();
		++argv;
	}
	return (0);
}
