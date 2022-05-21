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
-c db_dir
: specifies a database directory or a DAX device.  If the directory does not exist, it will be created.

-d
: enables debug mode.  In the debug mode, the server is executed in the foreground.

-f
: executes in the foreground.

-s db_size
: specifies a database size.  This option is only effective when using the pmemkv and fsdax.  Default is 256 MiB.

-p protocol
: specifies a protocol like sm, sockets, tcp, and verbs.  Default is sockets.

-h host
: specify hostname, IP address or interface name and the port number.  Before the port number, ':' is required.

-l log_file
: specifies a log file.

-P pid_file
: specifies a pid file.

-n vname
: specifies a vname which is used to construct a virtual name such as server_address:vname.

-N virtual_name
: specifies a virtual name.

-S server_info_file
: specifies a server info file where the server address will be written.

-t RPC_timeout_msec
: specifies a timeout for RPC in milliseconds.  Default is 0 (no timeout).

-T nthreads
: specifies the number of threads of the chfsd.  Default is 5.

-I niothreads
: specifies the number of I/O threads of the chfsd.  This option is effective with ABT-IO.  Default is 2.

-H heartbeat_interval
: specifies the interval of heartbeat in second.  Default is 10 seconds.

-L log_priority
: specifies the maximum log priority to report.  Default is notice.
