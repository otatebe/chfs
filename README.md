# CHFS - Consistent hashing file system

CHFS is a parallel consistent hashing file system.  File chunks are distributed among file servers using consistent hashing.

## Quick installation steps

1. Install Spack

       % git clone https://github.com/spack/spack.git
       % . spack/share/spack/setup-env.sh

2. Install Mochi-margo

       % git clone https://xgitlab.cels.anl.gov/sds/sds-repo.git
       % spack repo add sds-repo
       % spack install mochi-margo

3. (Optional) Install pmemkv

       # apt install libpmemkv-dev

4. Install Fuse

       # apt install libfuse-dev

5. Install CHFS

       % spack load mochi-margo
       % autoreconf -i
       % ./configure [--with-pmemkv] [--prefix=PREFIX]
       % make
       # make install

## How to create file system

1. Create CHFS

       % eval `chfsctl [-h hostfile] start`

   For details, see manual page of chfsctl.

## How to use

1. Mount the CHFS

       % chfuse <mount_point>

## Environment variable

- CHFS_SERVER - one of server addresses
- CHFS_CHUNK_SIZE - chunk size
- CHFS_RDMA_THRESH - RDMA transfer is used when the size is larger than or equal to CHFS_RDMA_THRESH
- CHFS_RPC_TIMEOUT_MSEC - RPC timeout in milliseconds
- CHFS_NODE_LIST_CACHE_TIMEOUT - node list cache timeout in seconds
- CHFS_LOG_PRIORITY - maximum log priority to report

## IOR and mdtest

1. Installation

       % git clone https://github.com/otatebe/ior.git -b feature/chfs
       % cd ior
       % ./bootstrap
       % spack load mochi-margo
       % ./configure --with-chfs=PREFIX [--prefix=PREFIX]
       % make
       # make install

2. How to use

       % spack load mochi-margo
       % mpirun -x LD_LIBRARY_PATH -x CHFS_SERVER ior -a CHFS [--chfs.chunk_size=SIZE]

## CHFS API

The following APIs are supported.

    int chfs_init(const char *server);
    int chfs_term();
    void chfs_set_chunk_size(int chunk_size);
    void chfs_set_get_rdma_thresh(int thresh);
    void chfs_set_rpc_timeout_msec(int timeout);
    void chfs_set_node_list_cache_timeout(int timeout);

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
    int chfs_unlink(const char *path);
    int chfs_mkdir(const char *path, mode_t mode);
    int chfs_rmdir(const char *path);
    int chfs_stat(const char *path, struct stat *st);
    int chfs_readdir(const char *path, void *buf,
            int (*filler)(void *, const char *, const struct stat *, off_t));
