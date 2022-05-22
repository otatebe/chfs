#!/bin/sh

set -eux

LANG=C
MDIR=/tmp/a

eval $(chfsctl -h hosts -m $MDIR -b $PWD/backend start)
chlist
cp chfs/configure backend
diff chfs/configure $MDIR/configure
s1=$(wc chfs/configure | awk '{ print $3 }')
s2=$(wc $MDIR/configure | awk '{ print $3 }')
[ $s1 = $s2 ]
s1=$(ls -l chfs/configure | awk '{ print $4 }')
s2=$(ls -l $MDIR/configure | awk '{ print $4 }')
[ $s1 = $s2 ]
chfind
mpirun -x LD_LIBRARY_PATH -x CHFS_SERVER -np 4 -hostfile hosts -map-by node ior -a CHFS -o /tmp/a/test -g
chfsctl -h hosts -m $MDIR stop

ls -l backend
rm backend/configure
rm backend/test

echo OK
