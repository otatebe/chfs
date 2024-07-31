#include <assert.h>
#include <mpi.h>

#define _(x) assert((x) == 0)

int
main(int argc, char *argv[])
{
	MPI_File fh;

	_(MPI_Init(&argc, &argv));
	_(MPI_File_open(MPI_COMM_WORLD, "chfs:test.txt", MPI_MODE_CREATE|MPI_MODE_WRONLY, MPI_INFO_NULL, &fh));
	_(MPI_File_close(&fh));
	_(MPI_Finalize());

	return 0;
}
