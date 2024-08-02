#!/bin/sh

echo Install IOR
set -eux

cd
[ -d ior ] || git clone https://github.com/otatebe/ior.git -b feature/chfs
cd ior
git pull > /dev/null || :
./bootstrap > /dev/null

[ -d build ] || mkdir build
cd build
../configure --prefix $HOME/local > /dev/null
make > /dev/null
make install > /dev/null
