#!/bin/sh

# usage: fill-scratch.sh full|onepage dir
#
# fills dir.  When onepage is specified, one page is left.

dd if=/dev/zero of=$2/fill bs=4k > /dev/null 2>&1
if [ $1 = onepage ]; then
	s=$(stat -c %s $2/fill)
	truncate -s $((s / 4096 * 4096 - 4096)) $2/fill
fi
exit 0
