#include "config.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <fnmatch.h>
#include <getopt.h>
#ifdef HAVE_MPI
#include <mpi.h>
#endif
#include <chfs.h>

static struct option options[] = {
	{ "name", required_argument, NULL, 'n' },
	{ "size", required_argument, NULL, 's' },
	{ "newer", required_argument, NULL, 'N' },
	{ "type", required_argument, NULL, 't' },
	{ "version", no_argument, NULL, 'V' },
#ifndef HAVE_MPI
	{ "mpi_rank", required_argument, NULL, 'R' },
	{ "mpi_size", required_argument, NULL, 'S' },
#endif
	{ 0, 0, 0, 0 }
};

static void
usage(void)
{
	fprintf(stderr, "usage: chfind [-qv] [dir ...] [-name pat] "
		"[-size size] [-newer file]\n\t[-type type] [-version]\n");
	exit(EXIT_FAILURE);
}

static struct {
	char *name, type, *newer, *size;
	struct stat newer_sb;
	int quiet, verbose;
	long size_prefix, size_unit, size_count;
} opt;

enum {
	FOUND,
	TOTAL,
	NUM_COUNT
};
static uint64_t local_count[NUM_COUNT];
#ifdef HAVE_MPI
static uint64_t total_count[NUM_COUNT];
#endif

static void
parse_size(char *str_size)
{
	char *s = str_size;
	long prefix = 0, count = 0, unit = 0;

	switch (*s) {
	case '-':
		prefix = -1;
		++s;
		break;
	case '+':
		prefix = 1;
		++s;
		break;
	}
	while (*s >= '0' && *s <= '9')
		count = 10 * count + (*s++ - '0');

	switch (*s) {
	case 'b':
		unit = 512;
		++s;
		break;
	case 'c':
		unit = 1;
		++s;
		break;
	case 'w':
		unit = 2;
		++s;
		break;
	case 'k':
		unit = 1024;
		++s;
		break;
	case 'M':
		unit = 1024 * 1024;
		++s;
		break;
	case 'G':
		unit = 1024 * 1024 * 1024;
		++s;
		break;
	case '\0':
		unit = 512;
		break;
	}
	if (*s) {
		fprintf(stderr, "invalid size: %s\n", str_size);
		exit(EXIT_FAILURE);
	}
	opt.size_prefix = prefix;
	opt.size_count = count;
	opt.size_unit = unit;
}

static int
match_size(size_t size)
{
	size_t tmp = size / opt.size_unit;

	if (size != tmp * opt.size_unit)
		return (0);

	switch (opt.size_prefix) {
	case -1:
		if (tmp < opt.size_count)
			return (1);
		break;
	case 0:
		if (tmp == opt.size_count)
			return (1);
		break;
	case 1:
		if (tmp > opt.size_count)
			return (1);
		break;
	}
	return (0);
}

static int
find(const char *name, const struct stat *st)
{
	if (opt.newer && (st->st_mtim.tv_sec < opt.newer_sb.st_mtim.tv_sec ||
		(st->st_mtim.tv_sec == opt.newer_sb.st_mtim.tv_sec &&
		 st->st_mtim.tv_nsec <= opt.newer_sb.st_mtim.tv_nsec)))
		return (0);

	if (opt.size && !match_size(st->st_size))
		return (0);

	if (opt.name && fnmatch(opt.name, name, 0))
		return (0);

	switch (opt.type) {
	case 'f':
		if (!S_ISREG(st->st_mode))
			return (0);
		break;
	case 'd':
		if (!S_ISDIR(st->st_mode))
			return (0);
		break;
	}
	local_count[FOUND]++;
	return (1);
}

struct dir {
	char *name;
	struct dir *next;
};

static struct dir *dir_head = NULL;
static struct dir **dir_tail = &dir_head;

static int
dir_list_push(char *name)
{
	struct dir *d = malloc(sizeof *d);

	if (d == NULL)
		return (-1);
	d->name = strdup(name);
	if (d->name == NULL) {
		free(d);
		return (-1);
	}
	d->next = NULL;
	*dir_tail = d;
	dir_tail = &d->next;
	return (0);
}

static char *
dir_list_pop(void)
{
	struct dir *d;
	char *name;

	if (dir_head == NULL)
		return (NULL);
	d = dir_head;
	dir_head = d->next;
	if (dir_head == NULL)
		dir_tail = &dir_head;
	name = d->name;
	free(d);
	return (name);
}

static int
filler(void *buf, const char *name, const struct stat *st, off_t off)
{
	char *d;

	local_count[TOTAL]++;

	if (name[0] == '.' && (name[1] == '\0' ||
		(name[1] == '.' && name[2] == '\0')))
			return (0);

	if (S_ISDIR(st->st_mode)) {
		d = malloc(strlen(buf) + 1 + strlen(name) + 1);
		sprintf(d, "%s/%s", (char *)buf, name);
		dir_list_push(d);
		free(d);
	}
	if (st->st_mode & CHFS_S_IFREP)
		return (0);
	if (find(name, st) && !opt.quiet)
		printf("%s/%s\n", (char *)buf, name);
	return (0);
}

int
main(int argc, char *argv[])
{
	int c, rank = 0, size = 1;
	char *d;
	struct stat sb;

#ifdef HAVE_MPI
	MPI_Init(&argc, &argv);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
#endif
	while ((c = getopt_long_only(argc, argv, "qv", options, NULL)) != -1) {
		switch (c) {
		case 'n':
			opt.name = optarg;
			break;
		case 'N':
			opt.newer = optarg;
			break;
		case 'q':
			opt.quiet = 1;
			break;
#ifndef HAVE_MPI
		case 'R':
			rank = atoi(optarg);
			break;
		case 'S':
			size = atoi(optarg);
			break;
#endif
		case 's':
			opt.size = optarg;
			parse_size(opt.size);
			break;
		case 't':
			opt.type = optarg[0];
			break;
		case 'v':
			opt.verbose++;
			break;
		case 'V':
			fprintf(stderr, "CHFS version %s\n", chfs_version());
			exit(0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	chfs_init(NULL);
	if (opt.newer)
		if (chfs_stat(opt.newer, &opt.newer_sb) &&
			lstat(opt.newer, &opt.newer_sb))
			perror(opt.newer), exit(EXIT_FAILURE);

	if (argc == 0) {
		if (chfs_stat(".", &sb)) {
			if (rank == 0)
				perror(".");
		} else {
			if (rank == 0) {
				if (find(".", &sb) && !opt.quiet)
					printf(".\n");
				local_count[TOTAL]++;
			}
			dir_list_push(".");
		}
	} else
		for (; argc > 0; --argc) {
			if (chfs_stat(*argv, &sb)) {
				if (rank == 0)
					perror(*argv);
				continue;
			}
			if (rank == 0) {
				if (find(*argv, &sb) && !opt.quiet)
					printf("%s\n", *argv);
				local_count[TOTAL]++;
			}
			dir_list_push(*argv++);
		}

	while ((d = dir_list_pop())) {
		if (size > 1)
			chfs_readdir_index(d, rank, d, filler);
		else
			chfs_readdir(d, d, filler);
		free(d);
	}
#ifdef HAVE_MPI
	MPI_Reduce(local_count, total_count, NUM_COUNT, MPI_LONG_LONG_INT,
		MPI_SUM, 0, MPI_COMM_WORLD);
#endif
	if (opt.verbose > 1)
		printf("[%d] %lu/%lu\n", rank, local_count[FOUND],
			local_count[TOTAL]);
#ifdef HAVE_MPI
	if (opt.verbose > 0 && rank == 0)
		printf("MATCHED %lu/%lu\n", total_count[FOUND],
			total_count[TOTAL]);
#else
	if (opt.verbose > 0 && rank == 0 && size == 1)
		printf("MATCHED %lu/%lu\n", local_count[FOUND],
			local_count[TOTAL]);
#endif
	chfs_term();
#ifdef HAVE_MPI
	MPI_Finalize();
#endif
	return (0);
}
