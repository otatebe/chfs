% chstsagein(1) CHFS
%
% January 30, 2023

# NAME
chstagein - stage-in files to CHFS

# SYNOPSIS
**chstagein** [_options_] _file_ ...

# DESCRIPTION
**chstagein** stages in files to CHFS in parallel in MPI.

# OPTIONS
-a
: enable asynchronous accesses.

-b _bufsize_
: specifies the buffer size.  Default is 1 MiB.

-c _chunksize_
: specifies the chunk size.

# ENVIRONMENT
CHFS_SERVER
: server addresses separated by ','

CHFS_BACKEND_PATH
: backend path

CHFS_SUBDIR_PATH
: directory in CHFS to be mounted

CHFS_CHUNK_SIZE
: chunk size.  Default is 64 KiB.

CHFS_ASYNC_ACCESS
: set 1 to enable asynchronous accesses.  Default is 0.

CHFS_RDMA_THRESH
: RDMA transfer is used when the size is larger than CHFS_RDMA_THRESH.  Zero means RDMA transfer is always used.  -1 means RDMA transfer is never used.  Default is 32 KiB.

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds.  Zero means no timeout.  Default is 30000 milliseconds (30 seconds).

CHFS_LOG_PRIORITY:
: maximum log priority to report.  Default is notice.

# EXAMPLES
The following example stages in all files in a backend directory.  **chstagein** can be executed with and without mpirun.

    $ cd <backend_directory>
    $ find . | xargs [ mpirun ... ] chstagein

In OpenMPI, several environment variables should be explicitly passed.

    $ mpirun -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH ... chstagein ...
