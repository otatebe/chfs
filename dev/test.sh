#!/bin/sh

set -eux

LANG=C
eval $(chfsctl -h hosts -m /tmp/a -b $PWD/backend start)
chlist
cp chfs/configure backend
diff chfs/configure /tmp/a/configure
s1=$(wc chfs/configure | awk '{ print $3 }')
s2=$(wc /tmp/a/configure | awk '{ print $3 }')
[ $s1 = $s2 ]
s1=$(ls -l chfs/configure | awk '{ print $4 }')
s2=$(ls -l /tmp/a/configure | awk '{ print $4 }')
[ $s1 = $s2 ]
chfind
chfsctl -h hosts -m /tmp/a stop

rm backend/configure

echo OK
