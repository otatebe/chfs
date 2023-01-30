% chstsagein(1) CHFS
%
% January 30, 2023

# NAME
chstagein - stage-in a file to CHFS

# SYNOPSIS
**chstagein** [_options_] _file_

# DESCRIPTION
**chstagein** stages in a file to CHFS.

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

CHFS_CHUNK_SIZE
: chunk size.  Default is 64 KiB.

CHFS_ASYNC_ACCESS
: set 1 to enable asynchronous accesses.  Default is 0.

CHFS_RDMA_THRESH
: RDMA transfer is used when the size is larger than or equal to CHFS_RDMA_THRESH.  Default is 32 KiB.

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds

CHFS_LOG_PRIORITY:
: maximum log priority to report
