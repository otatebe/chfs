#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include "chfs.h"
#include "log.h"

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-V] dir\n", progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *dir, *progname;
	int r, opt;

	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "V")) != -1) {
		switch (opt) {
		case 'V':
			fprintf(stderr, "CHFS version %s\n", chfs_version());
			exit(0);
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
	log_debug("rmdir %s", dir);
	r = chfs_rmdir(dir);
	if (r == -1)
		log_error("%s: cannot remove", dir);
	chfs_term();
	return (r);
}
