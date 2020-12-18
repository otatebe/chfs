% chfsctl(1) CHFS
%
% December 18, 2020

# NAME
chfsctl - manage CHFS servers

# SYNOPSIS
**chfsctl** [_options_] _mode_

# DESCRIPTION
**chfsctl** manages CHFS file servers for CHFS parallel consistent hashing file system.  The _mode_ should be start, stop, status or kill.  When the _mode_ is start, it executes CHFS servers and displays the environment variable to access the CHFS.

# OPTIONS
-c db_dir
: specifies a database directory.  If the directory does not exist, it will be created.  Default is /tmp/$USER.

-s db_size
: specifies a database size.  This option is only effective when using the pmemkv.  Default is 256 MiB.

-p protocol
: specifies a protocol like sm, sockets, tcp, and verbs.  Default is sockets.

-I interfaces
: specifies interfaces to execute chfsd when there are multiple interfaces such as "eno1 eno2".  In the case of InfiniBand, you can specify -I "$(ibstat -l)".

-L log_dir
: specifies a log directory.  Default is $HOME.

-h hostfile
: specify hostfile.

-O options
: specifies options for chfsd.
