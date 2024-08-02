#!/bin/sh

echo Install RDBench
set -eux

cd
[ -d rdbench ] || git clone https://github.com/range3/rdbench.git
cd rdbench
git pull > /dev/null || :

[ -d build ] || mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$HOME/local ..
make > /dev/null
make install > /dev/null
