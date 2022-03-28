# CHFS - Consistent hashing file system

CHFS is a parallel consistent hashing file system.  File chunks are distributed among file servers using consistent hashing.

## Quick installation steps

1. Install development kits

       # apt install build-essential
       # apt install cmake libtool pkg-config

1. Install Spack

       % git clone https://github.com/spack/spack.git
       % . spack/share/spack/setup-env.sh

   For details, see https://spack.readthedocs.io/

1. Install Mochi-margo

       % spack install mochi-margo

   For details, see https://mochi.readthedocs.io/

1. (Optional) Install pmemkv

       # apt install libpmemkv-dev
       # apt install libpmemobj-cpp-dev libmemkind-dev libtbb-dev

   For details, see https://pmem.io/pmemkv/

1. Install Fuse

       # apt install libfuse-dev

1. (Optional) Install pandoc

       # apt install pandoc

1. Install CHFS

       % spack load mochi-margo
       % autoreconf -i
       % ./configure [--prefix=PREFIX] [--with-pmemkv]
       % make
       # make install

## How to create file system

1. Create CHFS

       % eval `chfsctl [-h hostfile] start`

   For details, see manual page of chfsctl.

## How to use

1. Mount the CHFS

       % chfuse <mount_point>

   For details, see manual page of chfuse.

## Environment variable

- CHFS_SERVER - server addresses separated by ','
- CHFS_CHUNK_SIZE - chunk size
- CHFS_RDMA_THRESH - RDMA transfer is used when the size is larger than or equal to CHFS_RDMA_THRESH
- CHFS_RPC_TIMEOUT_MSEC - RPC timeout in milliseconds
- CHFS_NODE_LIST_CACHE_TIMEOUT - node list cache timeout in seconds
- CHFS_LOG_PRIORITY - maximum log priority to report

When you use pmemkv, devdax is desirable.  When you use fsdax, the following environment variable is recommended to touch every page of the persistent memory pool, while the start up time of chfsd becomes slow.

- PMEMOBJ_CONF="prefault.at_open=1;prefault.at_create=1"

## IOR and mdtest

1. Installation

       % git clone https://github.com/otatebe/ior.git -b feature/chfs
       % cd ior
       % ./bootstrap
       % spack load mochi-margo
       % ./configure --with-chfs=PREFIX [--prefix=PREFIX]
       % make
       # make install

1. How to use

       % spack load mochi-margo
       % mpirun -x PATH -x LD_LIBRARY_PATH -x CHFS_SERVER ior -a CHFS [--chfs.chunk_size=SIZE]

   Large chunk size, i.e. 1 MiB, should be specified for best performance.

## CHFS API

The following APIs are supported.

    int chfs_init(const char *server);
    int chfs_term();
    const char *chfs_version();
    void chfs_set_chunk_size(int chunk_size);
    void chfs_set_rdma_thresh(int thresh);
    void chfs_set_rpc_timeout_msec(int timeout_msec);
    void chfs_set_node_list_cache_timeout(int timeout_sec);

    int chfs_create(const char *path, int32_t flags, mode_t mode);
    int chfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
            int chunk_size);
    int chfs_open(const char *path, int32_t flags);
    int chfs_close(int fd);
    ssize_t chfs_pwrite(int fd, const void *buf, size_t size, off_t offset);
    ssize_t chfs_write(int fd, const void *buf, size_t size);
    ssize_t chfs_pread(int fd, void *buf, size_t size, off_t offset);
    ssize_t chfs_read(int fd, void *buf, size_t size);
    int chfs_fsync(int fd);
    int chfs_truncate(const char *path, off_t len);
    int chfs_unlink(const char *path);
    int chfs_mkdir(const char *path, mode_t mode);
    int chfs_rmdir(const char *path);
    int chfs_stat(const char *path, struct stat *st);
    int chfs_readdir(const char *path, void *buf,
            int (*filler)(void *, const char *, const struct stat *, off_t));
    int chfs_symlink(const char *target, const char *path);
    int chfs_readlink(const char *path, char *buf, size_t size);
