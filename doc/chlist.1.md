% chlist(1) CHFS
%
% December 18, 2020

# NAME
chlist - list CHFS servers

# SYNOPSIS
**chlist** [-c] [-s _server_]

# DESCRIPTION
**chlist** lists CHFS servers.

# CHLIST OPTIONS
-c
: list servers in CHFS_SERVER format.

-n num_servers
: specifies the number of servers to display.

-s server
: specifies a CHFS server.  The server can be specified by the CHFS_SERVER environment variable.

# ENVIRONMENT
CHFS_SERVER
: server addresses separated by ','

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds

CHFS_LOG_PRIORITY:
: maximum log priority to report
