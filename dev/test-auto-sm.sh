#!/bin/sh

set -eux

# Mercury auto_sm by chfsd -a.  Data transfers within a node use
# cross-memory attach, which needs ptrace_scope 0 or CAP_SYS_PTRACE.
[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
SBIN=$HOME/local/sbin
WRAPPER=
if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2> /dev/null || echo 0)" != 0 ]
then
	if ! command -v setcap > /dev/null; then
		echo skip auto_sm test: setcap not found
		exit 0
	fi
	cp $SBIN/chfsd $SBIN/chfsd-auto-sm
	sudo setcap cap_sys_ptrace+ep $SBIN/chfsd-auto-sm
	WRAPPER="-wrapper chfsd-auto-sm"
	# only chfsd has the capability.  Use RDMA for all data transfers,
	# where chfsd accesses the client memory
	export CHFS_RDMA_THRESH=0
fi
NAMES=/tmp/auto-sm-names.$$
DATA=/tmp/auto-sm-data.$$
st=0

start_auto_sm() {
	chfsctl -h hosts $OPT stop 2> /dev/null || :
	chfsctl -h hosts clean
	eval $(chfsctl -h hosts $OPT $WRAPPER -b $CHFS_BACKEND -O "-a" start)
	chlist
}

stop_auto_sm() {
	chfsctl -h hosts $OPT stop
	chfsctl -h hosts clean
}

start_auto_sm

# addresses include the shared-memory address, but virtual names do not
# since it changes every time
[ $(chlist | grep -c '#na+sm://') -eq $(chlist | wc -l) ] || st=1
chlist | awk '{ print $2 }' | sort > $NAMES
grep na+sm $NAMES && st=1

# regression test
test/test || st=1

# data transfer
for s in 1000 100000 3000000; do
	head -c $s /dev/urandom > $DATA
	$CFS cp $DATA $APATH/auto-sm-$s || st=1
	$CFS cmp $DATA $APATH/auto-sm-$s || st=1
	$CFS rm -f $APATH/auto-sm-$s
done
stop_auto_sm

# virtual names do not change after restart
start_auto_sm
chlist | awk '{ print $2 }' | sort | cmp - $NAMES || st=1
stop_auto_sm

rm -f $NAMES $DATA $BACKEND/auto-sm-* $SBIN/chfsd-auto-sm
exit $st
