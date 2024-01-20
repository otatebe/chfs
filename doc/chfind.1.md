% chfind(1) CHFS
%
% January 20, 2024

# NAME
chfind - search for files in directories in CHFS

# SYNOPSIS
**chfind** [_options_] _dir_ ... [_expression_]

# DESCRIPTION
**chfind** searches for files in the directories in CHFS in parallel
  in MPI.

# OPTIONS
-q
: no verbose message

-v
: display verbose messages

# EXPRESSION
-name _pattern_
: a shell wildcard pattern of entry name

-size _size_
: file size.  The + or - prefix shows greater than or less than.  The
'b', 'c', 'w', 'k', 'M' or 'G' suffix shows the unit of space of 512,
1, 2, 1024, 1024 * 1024, 1024 * 1024 * 1024, respectively.  The size
is rounding up in the unit.  The default unit is 512 bytes.

-newer _file_
: the modification time is newer than that of the specified file

-type _type_
: the entry type.  'f' and 'd' are supported for a regular file and a
directory, respectively.

-version
: display version

# ENVIRONMENT
CHFS_SERVER
: server addresses separated by ','

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds.  Zero means no timeout.  Default is
30000 milliseconds (30 seconds).

CHFS_LOG_PRIORITY:
: maximum log priority to report.  Default is notice.

# EXAMPLES

**chfind** can be executed with and without MPI.  In MPI, the process
count should be the same as the number of chfsd servers or more.

    $ mpirun -np $(chlist | wc -l) ... chfind ...

In OpenMPI, several environment variables should be explicitly passed.

    $ mpirun -np $(chlist | wc -l) -x CHFS_SERVER ... chfind ...

If MPI is not available, **chfindrun** will be installed to execute
**chfind** in parallel.

    $ chfindrun -hostfile hostfile [-output_dir dir] args ...
