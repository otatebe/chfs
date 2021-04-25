% chfsctl(1) CHFS
%
% December 21, 2020

# NAME
chfsctl - manage CHFS servers

# SYNOPSIS
**chfsctl** [_options_] _mode_

# DESCRIPTION
**chfsctl** manages CHFS file servers for CHFS parallel consistent hashing file system.  The _mode_ should be start, stop, status, kill or clean.  When the _mode_ is start, it executes CHFS servers and displays an environment variable to access the CHFS.  When the _mode_ is clean, it removes all files and directories in _scratch_dir_ specified by the -c option.

# OPTIONS
-A
: adds chfsd servers to an existing server pool.  CHFS_SERVER should be defined.

-c scratch_dir
: specifies a scratch directory.  If the directory does not exist, it will be created.  Default is /tmp/$USER.

-h hostfile
: specifies a hostfile.

-m mount_directory
: specifies a mount directory.

-p protocol
: specifies a protocol like sm, sockets, tcp, and verbs.  Default is sockets.

-s db_size
: specifies a database size.  This option is only effective when using the pmemkv.  Default is 256 MiB.

-D
: use devdax.

-C
: specifies CPU socket number.

-N virtual_name
: specifies a virtual name of servers.

-I interface
: specifies an interface to execute chfsd when there are multiple interfaces such as mlx5_0 and mlx5_1.

-L log_dir
: specifies a log directory.  If the directory does not exist, it will be created.  Default is $HOME.

-O options
: specifies options for chfsd.
