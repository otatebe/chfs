#!/bin/sh

# Test CHFS built with AddressSanitizer by
#	SANITIZE=address sh install-chfs.sh
# MPI, IOR and zpoline are not tested since they are not built with it.

set -eux

. ./test-env.sh

SANFLAGS="-g -fsanitize=address -fno-omit-frame-pointer"
REPORT=$PWD/log/asan
DATA=/tmp/asan-data.$$
rm -rf $REPORT
mkdir -p $REPORT
# errors are checked by the reports at the end.  exitcode=0 executes all
# tests to collect the reports
export ASAN_OPTIONS="detect_leaks=1:exitcode=0:log_path=$REPORT/asan"
# leaks in libraries used by CHFS are suppressed
export LSAN_OPTIONS="suppressions=$PWD/lsan.supp:print_suppressions=0"

(cd test && make clean && make SANFLAGS="$SANFLAGS")

. ./test-start.sh

# regression test
test/test

# stagein
(cd $BACKEND && chstagein README && mv README README.bak &&
	$CFS cat $APATH/README && mv README.bak README)

# data transfer
for s in 1000 100000 3000000; do
	head -c $s /dev/urandom > $DATA
	$CFS cp $DATA $APATH/asan-$s
	$CFS cmp $DATA $APATH/asan-$s
	$CFS rm -f $APATH/asan-$s
done

sh ./test-stop.sh

# write-back errors
sh ./test-flush-error.sh

# no space in a server
sh ./test-no-space.sh

(cd test && make clean)
rm -f $DATA $BACKEND/asan-*

# reports of AddressSanitizer
if [ -n "$(ls $REPORT)" ]; then
	cat $REPORT/*
	exit 1
fi
echo OK
