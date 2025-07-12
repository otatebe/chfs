#!/bin/sh

set -eux

# rdbench
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o chfs:$APATH/rdbench/o -i 10 -s 100
mpirun -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x LIBZPHOOK -x ROMIO_FSTYPE_FORCE=chfs: --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o $RPATH/rdbench2/o -i 10 -s 100
if [ X$CHFS_BACKEND = X/ ]; then
mpirun -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x LIBZPHOOK -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o $RPATH/rdbench3/o -i 10 -s 100
fi
