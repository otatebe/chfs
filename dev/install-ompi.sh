#!/bin/sh

set -eu

DISTDIR=$PWD

OMPI_BRANCH=v4.1.x-chfs

cd
#[ -d ompi ] || git clone https://github.com/otatebe/ompi.git -b $OMPI_BRANCH
#cd ompi
#git pull > /dev/null || :
#./autogen.pl

wget https://download.open-mpi.org/release/open-mpi/v4.1/openmpi-4.1.6.tar.bz2
tar xfp openmpi-4.1.6.tar.bz2
cd openmpi-4.1.6
patch -p1 < $DISTDIR/ompi/ad_chfs.patch
(cd ompi/mca/io/romio321/romio/ && ./autogen.sh)

rm -rf build
mkdir build
cd build
../configure --enable-mpirun-prefix-by-default --with-pmix=/usr/lib/x86_64-linux-gnu/pmix2 --with-io-romio-flags=--with-file-system=chfs --prefix $HOME/local > /dev/null
make -j $(nproc) > /dev/null
make install > /dev/null
make clean > /dev/null
