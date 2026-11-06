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

OMPI=openmpi-5.0.11

# When OMPI_ARCHIVE is specified, the installed files are archived in it,
# and installed from it next time without building
if [ -n "${OMPI_ARCHIVE:-}" ] && [ -f "$OMPI_ARCHIVE" ]; then
	tar xfp "$OMPI_ARCHIVE" -C $HOME/local
	exit 0
fi

[ -d $OMPI ] || {
	[ -f $OMPI.tar.bz2 ] || wget https://download.open-mpi.org/release/open-mpi/v5.0/$OMPI.tar.bz2
	tar xfp $OMPI.tar.bz2
	(cd $OMPI && patch -N -p1 < $DISTDIR/ompi/ad_chfs-5.0.patch)
	(cd $OMPI/3rd-party/romio341 && ./autogen.sh)
}
cd $OMPI

[ -d build ] || mkdir build
cd build
# use bundled packages.  Otherwise, packages installed by the previous
# installation are used as external packages, and configure fails
../configure --enable-prte-prefix-by-default \
	--with-io-romio-flags=--with-file-system=chfs+ufs+testfs \
	--with-libevent=internal --with-hwloc=internal \
	--with-pmix=internal --with-prrte=internal \
	--prefix $HOME/local > /dev/null
make -j $(nproc) > /dev/null
make install > /dev/null

if [ -n "${OMPI_ARCHIVE:-}" ]; then
	STAGE=$(mktemp -d)
	make install DESTDIR=$STAGE > /dev/null
	tar cfp "$OMPI_ARCHIVE" -C $STAGE$HOME/local .
	rm -rf $STAGE
fi
