. ./test-env.sh

# clean up
chfsctl -h hosts -m $MDIR stop 2> /dev/null
chfsctl -h hosts clean

# chfsctl start
eval $(chfsctl -h hosts -m $MDIR -b $BACKEND -f 2 -L log -O "-U 5" start)
chlist
