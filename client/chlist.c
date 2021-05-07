#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <margo.h>
#include "chfs.h"
#include "ring_list.h"

void
usage()
{
	fprintf(stderr, "usage: chlist [-c] [-s server]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char opt, *server = NULL;
	void (*display)(void) = ring_list_display;

	while ((opt = getopt(argc, argv, "cs:")) != -1) {
		switch (opt) {
		case 'c':
			display = ring_list_csv;
			break;
		case 's':
			server = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();

	chfs_init(server);
	display();

	return (0);
}
