% chfsd(8) CHFS
%
% December 18, 2020

# NAME
chfsd - CHFS server

# SYNOPSIS
**chfsd** [_options_] [_server_]

# DESCRIPTION
**chfsd** is a file server for CHFS parallel consistent hashing file system.  When _server_ is specified, it joins the server pool.  The server address is written to a server info file specified by the -S option.

# OPTIONS
-d
: enables debug mode

-c db_dir
: specifies a database directory.  If the directory does not exist, it will be created.

-s db_size
: specifies a database size.  This option is only effective when using the pmemkv.  Default is 256 MiB.

-p protocol
: specifies a protocol like sm, sockets, tcp, and verbs.  Default is sockets.

-h host
: specify hostname, IP address or interface name and the port number.  Before the port number, ':' is required.

-l log_file
: specifies a log file.

-S server_info_file
: specifies a server info file where the server address will be written.

-t RPC_timeout_msec
: specifies a timeout for RPC in milliseconds.  Default is 0 (no timeout).

-T nthreads
: specifies the number of threads of the chfsd.

-H heartbeat_interval
: specifies the interval of heartbeat in second.  Default is 10 seconds.

-L log_priority
: specifies the maximum log priority to report.  Default is notice.
