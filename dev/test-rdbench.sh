#!/bin/sh

set -eux

. ./test-env.sh

# rdbench
chmkdir $MDIR/rdbench
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o chfs:$MDIR/rdbench/o -i 10 -s 100
