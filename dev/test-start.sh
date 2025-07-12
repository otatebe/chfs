# clean up
[ X$MDIR = X ] && OPT= || OPT="-m $MDIR"
chfsctl -h hosts $OPT stop 2> /dev/null
chfsctl -h hosts clean

# chfsctl start
eval $(chfsctl -h hosts $OPT -b $CHFS_BACKEND -f 2 -L log -O "-U 10" start)
chlist
