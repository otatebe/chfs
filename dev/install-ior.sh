#!/bin/sh

set -eu

. $HOME/spack/share/spack/setup-env.sh
spack load mochi-margo
cd
[ -d ior ] || git clone https://github.com/otatebe/ior.git -b feature/chfs
cd ior
git pull > /dev/null || :
./bootstrap > /dev/null
./configure --prefix $HOME/local > /dev/null
make > /dev/null
make install > /dev/null
make clean > /dev/null
