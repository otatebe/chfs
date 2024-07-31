#!/bin/sh

set -eux

LANG=C
MDIR=/tmp/a
BACKEND=$PWD/backend

# clean up
chfsctl -h hosts -m $MDIR stop 2> /dev/null
chfsctl -h hosts clean

eval $(chfsctl -h hosts -m $MDIR -b $BACKEND -f 2 -L log start)
chlist
cp ~/chfs/configure $BACKEND
diff ~/chfs/configure $MDIR/configure
s1=$(wc ~/chfs/configure | awk '{ print $3 }')
s2=$(wc $MDIR/configure | awk '{ print $3 }')
[ $s1 = $s2 ]
s1=$(ls -l ~/chfs/configure | awk '{ print $5 }')
s2=$(ls -l $MDIR/configure | awk '{ print $5 }')
[ $s1 = $s2 ]
chfind $MDIR
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o $MDIR/test-chfs -g -w -r -R -G 12345 -k
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o chfs:$MDIR/test-mpiio -g -w -r -R -G 123456 -k
chmkdir $MDIR/rdbench
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o chfs:$MDIR/rdbench/o -s 1000 --novalidate
chfsctl -h hosts -m $MDIR stop

mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-chfs -g -r -R -G 12345
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-mpiio -g -r -R -G 123456

ls -l $BACKEND
rm $BACKEND/configure
rm -f $BACKEND/test-chfs $BACKEND/test-mpiio
ls -l $BACKEND/rdbench

chfsctl -h hosts -m $MDIR status

echo OK
