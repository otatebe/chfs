#!/bin/sh

set -eux

. ./test-env.sh

# ior in backend
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-chfs -g -r -R -G 12345
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-mpiio -g -r -R -G 123456
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-mpiio2 -g -r -R -G 123456
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-posix -g -r -R -G 1234567
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-posix2 -g -r -R -G 1234567
