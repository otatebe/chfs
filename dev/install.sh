#!/bin/sh

set -eu

# arguments are passed to install-chfs.sh
sh ./install-chfs.sh "$@"
sh ./install-ompi.sh
sh ./install-chfs.sh "$@"
sh ./install-zpoline.sh
sh ./install-ior.sh
sh ./install-rdbench.sh
