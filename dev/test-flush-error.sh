#!/bin/sh

set -eux

st=0

# write-back errors should be reported when all servers are stopped
. ./test-start.sh
test/flush_error "chfsctl -h hosts $OPT kill > /dev/null 2>&1" || st=1
chfsctl -h hosts $OPT stop > /dev/null 2>&1 || :
chfsctl -h hosts clean

rm -f $BACKEND/flush-error-*
exit $st
