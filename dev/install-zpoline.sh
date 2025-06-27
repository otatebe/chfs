#!/bin/sh

set -eu

echo Install CHFS-Zpoline
cd

set -x
PKG=chfs-zpoline
[ -d $PKG ] || git clone --recursive https://github.com/otatebe/$PKG.git
cd $PKG
git pull > /dev/null || :
autoreconf -i > /dev/null

[ -d build ] || mkdir build
cd build
../configure --prefix $HOME/local > /dev/null
make clean > /dev/null
make -j $(nproc) > /dev/null
make install > /dev/null
