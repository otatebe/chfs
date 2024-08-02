#!/bin/sh

set -eu

OPT=
while [ $# -gt 0 ]
do
	case $1 in
	pmemkv) OPT="$OPT --with-pmemkv" ;;
	*) OPT="$OPT $1" ;;
	esac
	shift
done

sh ./install-chfs.sh $OPT
sh ./install-ompi.sh
sh ./install-chfs.sh $OPT
sh ./install-ior.sh
sh ./install-rdbench.sh
