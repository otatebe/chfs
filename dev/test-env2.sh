echo / Backend setting
export LANG=C
export MDIR=
export CHFS_BACKEND=/
export BACKEND=$PWD/backend
export APATH=$PWD/backend
export RPATH=backend
sudo sysctl vm.mmap_min_addr=0
export LIBZPHOOK=$HOME/local/lib/libcz.so
export LIBZPDIRS="$PWD"
export CFS="env LD_PRELOAD=$HOME/local/lib/libzpoline.so"
