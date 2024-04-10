#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "murmur3.h"

#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_CMP(a, b) ((a[0] < b[0]) ? -1 : ((a[0] > b[0]) ? 1 : 0))
#define display_hash(hash) printf("%08x", hash[0])

#define MAX_DATASIZE	(1024 * 1024 * 1024)
#define BUFSIZE		65536

int
main(int argc, char *argv[])
{
	char *data, *d;
	ssize_t s;
	uint32_t h[1];

	data = d = malloc(MAX_DATASIZE);
	if (data == NULL)
		exit(EXIT_FAILURE);

	while (d - data + BUFSIZE <= MAX_DATASIZE &&
		(s = read(STDIN_FILENO, d, BUFSIZE)) > 0)
		d += s;

	HASH(data, d - data, h);
	display_hash(h);
	puts("");

	exit(0);
}
