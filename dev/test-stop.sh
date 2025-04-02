#!/bin/sh

set -eux

. ./test-env.sh

# chfsctl stop
chfsctl -h hosts -m $MDIR stop
