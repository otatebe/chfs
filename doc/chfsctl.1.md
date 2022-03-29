% chfsctl(1) CHFS
%
% December 21, 2020

# NAME
chfsctl - manage CHFS servers

# SYNOPSIS
**chfsctl** [_options_] _mode_

# DESCRIPTION
**chfsctl** manages CHFS file servers for CHFS parallel consistent hashing file system.  The _mode_ should be start, stop, status, kill or clean.  When the _mode_ is start, it executes CHFS servers and displays an environment variable to access the CHFS.  When the _mode_ is clean, it removes all files and directories in *scratch_dir* specified by the -c option.

# OPTIONS
-A
: adds chfsd servers to an existing server pool.  CHFS_SERVER should be defined.

-c scratch_dir
: specifies a scratch directory.  If the directory does not exist, it will be created.  Default is /tmp/$USER.

-h hostfile
: specifies a hostfile.

-m mount_directory
: specifies a mount directory.  When chfsctl start is executed multiple times with -A option, -m and -M options should be specified at every execution except the last execution of chfsctl start.  For the last execution, only -m option is specified without -M option.

-M
: do not mount

-b backend_directory
: specifies a backend directory to cache.

-f num_flush_threads
: specifies the number of flush threads.  Default is 1.

-p protocol
: specifies a protocol like sm, sockets, tcp, and verbs.  Default is sockets.

-s db_size
: specifies a database size.  This option is only effective when using the pmemkv and fsdax.  Default is 256 MiB.

-D
: use devdax.  In this case, a scratch directory specified by the -c option is a dax device, in which a pmem obj pool is created with the layout pmemkv.

-C
: specifies CPU socket number to execute.

-N virtual_name
: specifies a virtual name of servers.  Each server name consists of server address and virtual name.  Virtual name is useful to balance the load among servers when using consistent hashing.

-I interface
: specifies an interface to execute chfsd when there are multiple interfaces such as mlx5_0 and mlx5_1.

-L log_dir
: specifies a log directory.  If the directory does not exist, it will be created.  If not specified, log messages are sent to the system logger.

-n num_servers
: specifies the maximum number of first contact servers.  Default is 32.

-O options
: specifies options for chfsd.
