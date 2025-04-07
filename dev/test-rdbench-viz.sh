#!/bin/sh

set -eux

# viz.py
ENVDIR=~/local/rdbench-venv
[ -d $ENVDIR ] && {
        . $ENVDIR/bin/activate 2> /dev/null
        python rdbench/viz.py
        deactivate 2> /dev/null
}
