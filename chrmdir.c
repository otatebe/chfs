#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include "chfs.h"
#include "log.h"

int
main(int argc, char *argv[])
{
	char *dir;
	int r;

	if (argc < 2)
		fprintf(stderr, "usage: %s dir\n", basename(argv[0])),
		exit(EXIT_FAILURE);

	dir = argv[1];
	chfs_init(NULL);
	log_debug("rmdir %s", dir);
	r = chfs_rmdir(dir);
	if (r == -1)
		log_error("%s: cannot remove", dir);
	chfs_term();
	return (r);
}
