echo CHFUSE setting
export LANG=C
export MDIR=/tmp/a
export CHFS_BACKEND=$PWD/backend
export BACKEND=$PWD/backend
export APATH=/tmp/a
export RPATH=.
sudo sysctl vm.mmap_min_addr=0
export LIBZPHOOK=$HOME/local/lib/libcz.so
unset LIBZPDIRS
export CFS=
