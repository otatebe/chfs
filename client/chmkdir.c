#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include "chfs.h"
#include "log.h"

int
main(int argc, char *argv[])
{
	char *dir;
	mode_t mode;
	int r;

	if (argc < 3)
		fprintf(stderr, "usage: %s mode dir\n", basename(argv[0])),
		exit(EXIT_FAILURE);

	mode = strtol(argv[1], NULL, 8);
	dir = argv[2];
	chfs_init(NULL);
	log_debug("mkdir %o %s", mode, dir);
	r = chfs_mkdir(dir, mode);
	if (r == -1)
		log_error("%s: cannot create", dir);
	chfs_term();
	return (r);
}
