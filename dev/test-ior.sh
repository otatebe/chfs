#!/bin/sh

set -eux

# ior
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o $APATH/test-chfs -g -w -r -R -G 12345 -k
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o $RPATH/test-chfs2 -g -w -r -R -G 12345 -k

# MPIIO
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o chfs:$APATH/test-mpiio -g -w -r -R -G 123456 -k
mpirun -x ROMIO_FSTYPE_FORCE=chfs: --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o $RPATH/test-mpiio2 -g -w -r -R -G 123456 -k
mpirun -np 4 -hostfile hosts -map-by node sudo sysctl vm.mmap_min_addr=0
if [ X$CHFS_BACKEND = X/ ]; then
mpirun -x LIBZPDIRS -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o $RPATH/test-mpiio3 -g -w -r -R -G 123456 -k
fi

# POSIX
if [ X$MDIR = X ]; then
mpirun -x PATH -x LIBZPDIRS -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o $APATH/test-posix -g -w -r -R -G 1234567 -k
else
mpirun -x PATH -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o /chfs$APATH/test-posix -g -w -r -R -G 1234567 -k
fi
mpirun -x PATH -x LIBZPDIRS -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o $RPATH/test-posix2 -g -w -r -R -G 1234567 -k
