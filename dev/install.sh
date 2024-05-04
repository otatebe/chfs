#!/bin/sh

set -eu

OPT=
while [ $# -gt 0 ]
do
	case $1 in
	pmemkv) OPT="$OPT --with-pmemkv" ;;
	*) OPT="$OPT $1" ;;
	esac
	shift
done

cd ~/chfs

set -x
autoreconf -i
rm -rf build
mkdir build
cd build
../configure --prefix $HOME/local $OPT > /dev/null
make clean > /dev/null
make -j $(nproc) > /dev/null
make install > /dev/null
