#!/bin/sh

set -eux

. ./test-env.sh

# ior
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o $MDIR/test-chfs -g -w -r -R -G 12345 -k

mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o chfs:$MDIR/test-mpiio -g -w -r -R -G 123456 -k
mpirun -x ROMIO_FSTYPE_FORCE=chfs: --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o test-mpiio2 -g -w -r -R -G 123456 -k

mpirun -np 4 -hostfile hosts -map-by node sudo sysctl vm.mmap_min_addr=0
export LIBZPHOOK=$HOME/local/lib/libcz.so
mpirun -x PATH -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o /chfs$MDIR/test-posix -g -w -r -R -G 1234567 -k
mpirun -x PATH -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o test-posix2 -g -w -r -R -G 1234567 -k
