#!/bin/sh

set -eux

. ./test-env.sh

trap 'rm -f $BACKEND/test-*' 0 1 2 15

# test
(cd test && make)

# chfsctl start
. ./test-start.sh

# regression test
test/test

# stagein
(cd $BACKEND && chstagein README && mv README README.bak &&
	cat $MDIR/README && mv README.bak README)

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
sh ./test-ior.sh

# rdbench
sh ./test-rdbench.sh

# chfsctl stop
sh ./test-stop.sh

# ior in backend
sh ./test-ior-verify.sh

ls -l $BACKEND
rm $BACKEND/configure

# viz.py
sh ./test-rdbench-viz.sh

ls -l $BACKEND/rdbench
rm -rf $BACKEND/rdbench

# chfsctl status
chfsctl -h hosts -m $MDIR status

echo OK
