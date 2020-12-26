% chfsctl(1) CHFS
%
% December 21, 2020

# NAME
chfsctl - manage CHFS servers

# SYNOPSIS
**chfsctl** [_options_] _mode_

# DESCRIPTION
**chfsctl** manages CHFS file servers for CHFS parallel consistent hashing file system.  The _mode_ should be start, stop, status or kill.  When the _mode_ is start, it executes CHFS servers and displays an environment variable to access the CHFS.

# OPTIONS
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

-N virtual_names
: specifies virtual names of servers.

-I interfaces
: specifies interfaces to execute chfsd when there are multiple interfaces such as "eno1 eno2".  In the case of InfiniBand, you can specify -I "$(ibstat -l)".

-L log_dir
: specifies a log directory.  Default is $HOME.

-O options
: specifies options for chfsd.
