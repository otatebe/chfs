#!/bin/sh

set -eux

st=0

# write-back errors should be reported when all servers are stopped
. ./test-start.sh
test/flush_error "chfsctl -h hosts $OPT kill > /dev/null 2>&1" || st=1
chfsctl -h hosts $OPT stop > /dev/null 2>&1 || :
chfsctl -h hosts clean

# close(2) via chfuse should report the error.  Stop only chfsd
if [ X$MDIR != X ]; then
	. ./test-start.sh
	READY=/tmp/flush-error-ready.$$
	GO=/tmp/flush-error-go.$$
	rm -f $READY $GO
	python3 test/close_error.py $MDIR/flush-error-fuse $READY $GO &
	pid=$!
	while [ ! -f $READY ] && kill -0 $pid 2> /dev/null; do sleep 0.1; done
	for h in $(cat hosts); do ssh $h pkill -9 -x chfsd || :; done
	touch $GO
	wait $pid || st=1
	rm -f $READY $GO
	chfsctl -h hosts $OPT kill > /dev/null 2>&1 || :
	chfsctl -h hosts clean
fi
rm -f $BACKEND/flush-error-*
exit $st
