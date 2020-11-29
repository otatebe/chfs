#include <stdio.h>
#include <margo.h>
#include "chfs.h"
#include "ring_list.h"

int
main(int argc, char *argv[])
{
	chfs_init(argv[1]);
	ring_list_display();

	return (0);
}
