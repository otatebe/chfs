#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include "chfs.h"
#include "log.h"

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-m mode] dir\n", progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *dir, *progname;
	mode_t mode = 0755;
	int r, opt;

	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "m:")) != -1) {
		switch (opt) {
		case 'm':
			mode = strtol(optarg, NULL, 8);
			break;
		default:
			usage(progname);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage(progname);

	dir = argv[0];
	chfs_init(NULL);
	log_debug("mkdir -m %o %s", mode, dir);
	r = chfs_mkdir(dir, mode);
	if (r == -1)
		log_error("%s: cannot create", dir);
	chfs_term();
	return (r);
}
