#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <margo.h>
#include "chfs.h"
#include "ring_list.h"

void
usage()
{
	fprintf(stderr, "usage: chlist [-c] [-n #servers] [-s server] [-V]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *server = NULL;
	int opt, num_servers = 0;
	void (*display)(int) = ring_list_display;

	while ((opt = getopt(argc, argv, "cn:s:V")) != -1) {
		switch (opt) {
		case 'c':
			display = ring_list_csv;
			break;
		case 'n':
			num_servers = atoi(optarg);
			break;
		case 's':
			server = optarg;
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

	if (argc > 0)
		usage();

	chfs_init(server);
	display(num_servers);
	chfs_term();

	return (0);
}
