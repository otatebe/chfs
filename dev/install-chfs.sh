#!/bin/sh

set -eu

# pmemkv is an alias of --with-pmemkv.  Other arguments are passed to
# configure as they are
for a
do
	shift
	case $a in
	pmemkv) set -- "$@" --with-pmemkv ;;
	*) set -- "$@" "$a" ;;
	esac
done

# SANITIZE=address builds CHFS with AddressSanitizer in build-address.
# The option is added to CC and MPICC since libtool drops it from LDFLAGS
BUILD=build
if [ -n "${SANITIZE:-}" ]; then
	SANFLAGS="-fsanitize=$SANITIZE -fno-omit-frame-pointer"
	CC="${CC:-gcc} $SANFLAGS"
	CFLAGS="${CFLAGS:--g -O1}"
	export CC CFLAGS
	if command -v ${MPICC:-mpicc} > /dev/null; then
		MPICC="${MPICC:-mpicc} $SANFLAGS"
		export MPICC
	fi
	BUILD=build-$SANITIZE
fi

echo Install CHFS
cd ~/chfs

set -x
autoreconf -i

[ -d $BUILD ] || mkdir $BUILD
cd $BUILD
../configure --prefix $HOME/local "$@" > /dev/null
# show the configuration since the output of configure is discarded
grep -E '^(#define|/\* #undef) (USE_|HAVE_MPI|ENABLE_)' lib/config.h || :
grep -E '^(CC|MPICC|LIBPMEMKV_LIBS|ABT_IO_LIBS) =' Makefile || :
make -j $(nproc) > /dev/null
make install > /dev/null
