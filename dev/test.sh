#!/bin/sh

set -eux

LANG=C
MDIR=/tmp/a
BACKEND=$PWD/backend

trap 'rm -f $BACKEND/test-*' 0 1 2 15

# test
(cd test && make clean && make)

# clean up
chfsctl -h hosts -m $MDIR stop 2> /dev/null
chfsctl -h hosts clean

# chfsctl start
eval $(chfsctl -h hosts -m $MDIR -b $BACKEND -f 2 -L log start)
chlist

# regression test
test/test

# stagein
(cd $BACKEND; chstagein README)

# cache
cp ~/chfs/configure $BACKEND
diff ~/chfs/configure $MDIR/configure
s1=$(wc ~/chfs/configure | awk '{ print $3 }')
s2=$(wc $MDIR/configure | awk '{ print $3 }')
[ $s1 = $s2 ]
s1=$(ls -l ~/chfs/configure | awk '{ print $5 }')
s2=$(ls -l $MDIR/configure | awk '{ print $5 }')
[ $s1 = $s2 ]

# chfind
chfind $MDIR

# ior
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o $MDIR/test-chfs -g -w -r -R -G 12345 -k

mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a MPIIO -o chfs:$MDIR/test-mpiio -g -w -r -R -G 123456 -k

mpirun -np 4 -hostfile hosts -map-by node sudo sysctl vm.mmap_min_addr=0
export LIBZPHOOK=$HOME/local/lib/libcz.so
mpirun -x PATH -x LIBZPHOOK -x LD_PRELOAD=$HOME/local/lib/libzpoline.so -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a POSIX -o /chfs/$MDIR/test-posix -g -w -r -R -G 1234567 -k

# rdbench
chmkdir $MDIR/rdbench
mpirun --mca io romio321 -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node rdbench -o chfs:$MDIR/rdbench/o -s 400 --novalidate

# chfsctl stop
chfsctl -h hosts -m $MDIR stop

# ior in backend
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-chfs -g -r -R -G 12345
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-mpiio -g -r -R -G 123456
mpirun -x PATH -np 4 -hostfile hosts -map-by node ior -o $BACKEND/test-posix -g -r -R -G 1234567

ls -l $BACKEND
rm $BACKEND/configure

# viz.py
ENVDIR=~/rdbench-venv
[ -d $ENVDIR ] && {
	. $ENVDIR/bin/activate 2> /dev/null
	python rdbench/viz.py
	deactivate 2> /dev/null
}
ls -l $BACKEND/rdbench
rm -rf $BACKEND/rdbench

# chfsctl status
chfsctl -h hosts -m $MDIR status

echo OK
