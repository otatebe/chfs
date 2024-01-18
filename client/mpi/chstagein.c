#include "config.h"
#include <unistd.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_MPI
#include <mpi.h>
#endif
#include <chfs.h>
#include "log.h"

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-b bufsize] [-c chunk_size] file ...\n",
		progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *file, *progname;
	int r, opt, rank = 0, size = 1;

#ifdef HAVE_MPI
	MPI_Init(&argc, &argv);
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
#endif
	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "ab:c:")) != -1) {
		switch (opt) {
		case 'a':
			chfs_set_async_access(1);
			break;
		case 'b':
			chfs_stagein_set_buf_size(strtol(optarg, NULL, 0));
			break;
		case 'c':
			chfs_set_chunk_size(strtol(optarg, NULL, 0));
			break;
		default:
			usage(progname);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage(progname);

	r = chfs_init(NULL);
	if (r < 0) {
		fprintf(stderr, "chfs_init fails\n");
		exit(EXIT_FAILURE);
	}
	argc -= rank;
	argv += rank;
	while (argc > 0) {
		file = argv[0];
		log_debug("%s %s", progname, file);
		r = chfs_stagein(file);
		if (r < 0)
			perror(file);
		argc -= size;
		argv += size;
	}
	chfs_term();
#ifdef HAVE_MPI
	MPI_Finalize();
#endif
	exit(r);
}
