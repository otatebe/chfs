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
: specifies a database size.  This option is only effective when using the pmemkv and fsdax.  Default is 1 GiB.

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

# EXAMPLES
Here is an example to execute chfsd on host listed in hostfile, which utilizes the devdax device /dev/dax0.0.  /back/end/dir is a target directory to be cached from and flushed to automatically on the backend file system.  It is mounted at /tmp/chfs on every node.

    % eval `chfsctl -h hostfile -p verbs -D -c /dev/dax0.0 -b /back/end/dir -m /tmp/chfs start`

Here is an example to execute two chfsds on host listed in hostfile.  One is executed on CPU 0 and utilizes the devdax device /dev/dax0.0 and InfiniBand interface mlx5_0, the other is executed on CPU 1 and utilizes /dev/dax0.1 and mlx5_1.  Except the last execution -M option is required.  The second or later execution of chfctl requires -A option.

    % eval `chfsctl -h hostfile -p verbs -D -c /dev/dax0.0 -C 0 -I mlx5_0 -b /back/end/dir -m /tmp/chfs -M start`
    % eval `chfsctl -h hostfile -p verbs -D -c /dev/dax1.0 -C 1 -I mlx5_1 -b /back/end/dir -m /tmp/chfs -A start`
