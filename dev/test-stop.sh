#!/bin/sh

# chfsctl stop
[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
chfsctl -h hosts $OPT stop
