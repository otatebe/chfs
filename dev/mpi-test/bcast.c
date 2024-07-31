#include <assert.h>
#include <mpi.h>

#define _(x) assert((x) == 0)

int
main(int argc, char *argv[])
{
	int n = 10;

	_(MPI_Init(&argc, &argv));
	_(MPI_Bcast(&n, 1, MPI_INT, 0, MPI_COMM_WORLD));
	_(MPI_Finalize());

	return 0;
}
