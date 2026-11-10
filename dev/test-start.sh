# clean up
[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
chfsctl -h hosts $OPT stop 2> /dev/null
chfsctl -h hosts clean

# chfsctl start.  ASAN_OPTIONS and LSAN_OPTIONS are passed to chfsd and
# chfuse for test-asan.sh
XOPT=
[ X${ASAN_OPTIONS:-} = X ] || XOPT="$XOPT -x ASAN_OPTIONS=$ASAN_OPTIONS"
[ X${LSAN_OPTIONS:-} = X ] || XOPT="$XOPT -x LSAN_OPTIONS=$LSAN_OPTIONS"
eval $(chfsctl -h hosts $OPT $XOPT -b $CHFS_BACKEND -f 2 -L log -O "-U 10" \
	start)
chlist
