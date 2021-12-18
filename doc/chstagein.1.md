% chstsagein(1) CHFS
%
% December 18, 2021

# NAME
chstagein - stage-in a file to CHFS

# SYNOPSIS
**chstagein** [-m _bufsize_] _src_ _dest_

# DESCRIPTION
**chstagein** stages in a file to CHFS.

# OPTIONS
-m _bufsize_
: specifies the buffer size

# ENVIRONMENT
CHFS_SERVER
: server addresses separated by ','

CHFS_RPC_TIMEOUT_MSEC
: RPC timeout in milliseconds

CHFS_LOG_PRIORITY:
: maximum log priority to report
