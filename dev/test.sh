#!/bin/sh

set -eux

LANG=C
MDIR=/tmp/a
BACKEND=$HOME/chfs/dev/backend

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
chfind
mpirun -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH -np 4 -hostfile hosts -map-by node ior -a CHFS -o /tmp/a/test -g -w -r -R -G 12345
chfsctl -h hosts -m $MDIR stop

ls -l $BACKEND
rm $BACKEND/configure
rm -f $BACKEND/test

chfsctl -h hosts -m $MDIR status

echo OK
