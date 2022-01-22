#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <chfs.h>
#include <log.h>

static int opt_bufsize = 1024 * 1024;
static int opt_chunk_size = 64 * 1024;

int
stagein(char *src, char *dst)
{
	struct stat sb;
	int s, d, r, rr = 0, st = -1;
	char *buf;

	buf = malloc(opt_bufsize);
	if (buf == NULL) {
		log_error("no memory");
		return (-1);
	}
	if (stat(src, &sb) == -1 || (s = open(src, O_RDONLY)) == -1) {
		perror(src);
		goto free_buf;
	}
	d = chfs_create_chunk_size(dst, O_WRONLY|CHFS_O_CACHE, sb.st_mode,
		opt_chunk_size);
	if (d < 0) {
		log_error("%s: cannot create", dst);
		goto close_s;
	}

	r = read(s, buf, opt_bufsize);
	while (r > 0) {
		rr = chfs_write(d, buf, r);
		if (rr < 0 || r != rr)
			break;
		r = read(s, buf, opt_bufsize);
	}
	if (r == 0)
		st = 0;
	else if (r < 0)
		log_error("read error");
	else if (rr < 0 || r != rr)
		log_error("write error");

	chfs_close(d);
close_s:
	close(s);
free_buf:
	free(buf);

	return (st);
}

void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-b bufsize] [-c chunk_size] src dest\n",
		progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char *src, *dst, *progname;
	int r, opt;

	progname = basename(argv[0]);

	while ((opt = getopt(argc, argv, "b:c:")) != -1) {
		switch (opt) {
		case 'b':
			opt_bufsize = strtol(optarg, NULL, 8);
			break;
		case 'c':
			opt_chunk_size = strtol(optarg, NULL, 8);
			break;
		default:
			usage(progname);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage(progname);

	src = argv[0];
	dst = argv[1];

	r = chfs_init(NULL);
	if (r < 0) {
		fprintf(stderr, "chfs_init fails\n");
		exit(EXIT_FAILURE);
	}
	log_debug("%s -b %d %s %s", progname, opt_bufsize, src, dst);
	r = stagein(src, dst);
	chfs_term();
	exit(r);
}
