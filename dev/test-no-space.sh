#!/bin/sh

# when the scratch directory of a server is full, data should be written
# to the backend, and can be read via CHFS

set -eux

[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
HOST=$(tail -1 hosts)
DIR=/tmp/$(id -un)
st=0

run() {
	chfsctl -h hosts $OPT stop > /dev/null 2>&1 || :
	chfsctl -h hosts clean
	ssh $HOST sudo mount -t tmpfs -o size=2m,uid=$(id -u),gid=$(id -g) \
		tmpfs $DIR
	# no flush thread to keep dirty data in the chunk
	eval $(chfsctl -h hosts $OPT -b $CHFS_BACKEND -f 0 -L log start)
	FILL="ssh $HOST sh $PWD/test/fill-scratch.sh $4 $DIR"
	test/no_space $1 $2 $3 "$FILL" || st=1
	chfsctl -h hosts $OPT kill > /dev/null 2>&1 || :
	chfsctl -h hosts clean
	ssh $HOST sudo umount $DIR
	rm -f $BACKEND/no-space-test
}

# chunk_size async dirty fill
run 4096 0 0 full
run 4096 1 0 full
run 8192 0 0 onepage
run 8192 1 0 onepage
run 8192 0 1 full
exit $st
