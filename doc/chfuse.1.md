% chfuse(1) CHFS
%
% December 18, 2020

# NAME
chfuse - mount CHFS

# SYNOPSIS
**chfuse** [_options_] <mount_point>

# DESCRIPTION
**chfuse** mounts a CHFS parallel consistent hashing file system.

# CHFUSE OPTIONS
\--server=CHFS_SERVER
: specifies a CHFS server.  The server can be specified by the CHFS_SERVER environment variable.

# ENVIRONMENT
CHFS_SERVER
: one of server addresses

CHFS_CHUNK_SIZE
: chunk size

CHFS_RDMA_THRESH
: RDMA transfer used when the size is larger than CHFS_RDMA_THRESH

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds

CHFS_LOG_PRIORITY:
: max log priority to report
