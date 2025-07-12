#!/bin/sh

set -eux

ENV=./test-env.sh
[ $# -gt 0 ] && ENV=./test-env2.sh

. $ENV

trap 'rm -f $BACKEND/test-*' 0 1 2 15

# test
(cd test && make)

# chfsctl start
. ./test-start.sh

# regression test
test/test

# stagein
(cd $BACKEND && chstagein README && mv README README.bak &&
	$CFS cat $APATH/README && mv README.bak README)

# cache
cp ~/chfs/configure $BACKEND
$CFS diff ~/chfs/configure $APATH/configure
rm $BACKEND/configure
s1=$(wc ~/chfs/configure | awk '{ print $3 }')
s2=$($CFS wc $APATH/configure | awk '{ print $3 }')
[ $s1 = $s2 ]
s1=$(ls -l ~/chfs/configure | awk '{ print $5 }')
s2=$($CFS ls -l $APATH/configure | awk '{ print $5 }')
[ $s1 = $s2 ]

# chfind
chfind $APATH

# ior
sh ./test-ior.sh

# rdbench
sh ./test-rdbench.sh

# chfsctl stop
sh ./test-stop.sh

# ior in backend
sh ./test-ior-verify.sh

ls -l $BACKEND

# viz.py
sh ./test-rdbench-viz.sh

ls -l $BACKEND/rdbench*
rm -rf $BACKEND/rdbench*

# chfsctl status
[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
chfsctl -h hosts $OPT status

echo OK
