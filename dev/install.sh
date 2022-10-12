#!/bin/sh

set -eu

. $HOME/spack/share/spack/setup-env.sh
spack load mochi-margo
cd ~/chfs
autoreconf -i
./configure --prefix $HOME/local > /dev/null
make clean > /dev/null
make > /dev/null
make install > /dev/null
