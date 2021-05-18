% chmkdir(1) CHFS
%
% December 21, 2020

# NAME
chmkdir - create a directory in CHFS

# SYNOPSIS
**chmkdir** [-m _mode_] _directory_

# DESCRIPTION
**chmkdir** creates a directory in CHFS.

# OPTIONS
-m _mode_
: specifies the mode

# ENVIRONMENT
CHFS_SERVER
: server addresses separated by ','

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds

CHFS_LOG_PRIORITY:
: maximum log priority to report
