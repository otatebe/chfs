#!/bin/sh

echo Insatall Open MPI
set -eux

DISTDIR=$PWD

cd
#OMPI_BRANCH=v4.1.x-chfs
#[ -d ompi ] || git clone https://github.com/otatebe/ompi.git -b $OMPI_BRANCH
#cd ompi
#git pull > /dev/null || :
#./autogen.pl

OMPI=openmpi-4.1.6
[ -d $OMPI ] || {
	[ -f $OMPI.tar.bz2 ] || wget https://download.open-mpi.org/release/open-mpi/v4.1/$OMPI.tar.bz2
	tar xfp $OMPI.tar.bz2
	(cd $OMPI && patch -N -p1 < $DISTDIR/ompi/ad_chfs.patch)
	(cd $OMPI/ompi/mca/io/romio321/romio/ && ./autogen.sh)
}
cd $OMPI

[ -d build ] || mkdir build
cd build
../configure --enable-mpirun-prefix-by-default --with-pmix=/usr/lib/x86_64-linux-gnu/pmix2 --with-io-romio-flags=--with-file-system=chfs --prefix $HOME/local > /dev/null
make -j $(nproc) > /dev/null
make install > /dev/null
