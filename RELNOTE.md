# Release note for CHFS/Cache 3.0.0 (2023/9/11)

CHFS/Cache is a parallel caching file system for node-local storages based on CHFS ad hoc parallel file system.  It provides a caching mechanism against a backend parallel file system.  Files in the backend parallel file system are automatically cached.  Output files are automatically flushed.

## How to create file system

       % eval `chfsctl [-h hostfile] [-p verbs] [-D] [-c /dev/dax0.0] [-b /back/end/path] [-m /mount/point] start`

The backend directory typically in a parallel file system can be specified by the -b option.  Files in the backend directory can be transparently accessed by CHFS.  For efficient access, files can be staged-in by `chstagein` command beforehand.  The output files will be flushed automatically to the backend directory.  It is possible to ensure flushing all dirty files by `chfs_sync()` or `chfsctl stop`.

## Technical details

Osamu Tatebe, Hiroki Ohtsuji, "[Caching Support for CHFS Node-local Persistent Memory File System](https://ieeexplore.ieee.org/document/9835238)", Proceedings of 3rd Workshop on Extreme-Scale Storage and Analysis (ESSA 2022), pp.1103-1110, 2022

# Release note for CHFS 2.1.2 (2023/9/11)

## New API
- chfs_initialized() - check whether chfs_init() is called or not

## Updated features
- chfs_init() - display parameters in info level

## Bug fixes
- chfs_open() - return EISDIR when opening a directory

# Release note for CHFS 2.1.1 (2023/7/6)

## Updated features
- chfsctl - -NUMACTL option to specify options for numactl

## Bug fixes
- fix chfs_pread may return no such file or directory

# Release note for CHFS 2.1.0 (2023/5/11)

## New environment variables
- CHFS_LOOKUP_LOCAL - connect to a local chfsd only

## New features
- chfsctl - -x option to export environment variable
- chfsctl - -i option to specify an interval in seconds to execute chfsd

## Updated features
- libchfs - randomize order for RPCs for all servers
- chfsctl - warn if less number of servers running

## Bug fixes
- fix compilation error in gcc 9.4.0
- chfsd - chfsd does not terminate
- chfsd - chfs_symlink may fail

# Release note for CHFS 2.0.0 (2022/10/21)

## New commands
- chfind - parallel find

## New environment variables
- CHFS_ASYNC_ACCESS - enable asynchronous read and write
- CHFS_BUF_SIZE - specify client buffer size.  Default is zero.

## New APIs
- chfs_seek - reposition read/write file offset
- chfs_readdir_index - read a directory in a specified server

## New features
- support pkgconfig
- support rpath
- Docker containers for developers

## Updated features
- chfs_unlink - improve performance
- change defaults.  Default chunk size is 64 KiB.

## Bug fixes
- libchfs - chfs_init returns no server when it is called more than the number of servers
- chfsd - fix memory leak when margo_get_input fails
- chfsd - fix election sometimes failing
- chfsd - introduce lock in KV backend
- chfsd - fix segfaults when shutting down

# Release note for CHFS 1.0.0 (2022/3/29)

CHFS is a parallel consistent hashing file system created instantly using node-local storages such as persistent memory and NVMe SSD.  It exploits the performance of persistent memory using persistent in-memory key-value store pmemkv.  For NVMe SSD, it uses the POSIX backend.  It supports InfiniBand verbs for high performance data access.

## How to create file system

    % eval `chfsctl [-h hostfile] [-p verbs] [-D] [-c /dev/dax0.0] [-m /mount/point] start`

This executes chfsd servers and mounts the CHFS at /mount/point on hosts specified by the hostfile.  The -p option specifies a communication protocol.  The -c option specifies a devdax device or a scratch directory on each host.

For the devdax device, -D option is required.  A pmem obj pool should be created with the layout pmemkv by `pmempool create -l pmemkv obj /dev/dax0.0`.  For user-level access, the permission of the device is modified; bad block check is disabled by `pmempool feature --disable CHECK_BAD_BLOCKS /dev/dax0.0`.

chfsctl outputs the setting of CHFS_SERVER environment variable, which is used to execute chfuse and CHFS commands.

For details, see [manual page of chfsctl](doc/chfsctl.1.md).

## Technical details

Osamu Tatebe, Kazuki Obata, Kohei Hiraga, Hiroki Ohtsuji, "[CHFS: Parallel Consistent Hashing File System for Node-local Persistent Memory](https://dl.acm.org/doi/fullHtml/10.1145/3492805.3492807)", Proceedings of the ACM International Conference on High Performance Computing in Asia-Pacific Region (HPC Asia 2022), pp.115-124, 2022
