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
: specifies a CHFS server.  The server can be specified by the CHFS_SERVER or CHFS_SERVERS environment variable.

# ENVIRONMENT
CHFS_SERVER
: one of server addresses

CHFS_SERVERS
: server addresses separated by ','

CHFS_CHUNK_SIZE
: chunk size.  Default is 4 KiB.

CHFS_RDMA_THRESH
: RDMA transfer is used when the size is larger than or equal to CHFS_RDMA_THRESH.  Default is 2 KiB.

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds.  Default is 0 (no timeout).

CHFS_NODE_LIST_CACHE_TIMEOUT
: node list cache timeout in seconds.  Default is 120 seconds.

CHFS_LOG_PRIORITY:
: maximum log priority to report.  Default is notice.
