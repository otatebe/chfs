#!/bin/sh

set -e

. spack/share/spack/setup-env.sh
spack load mochi-margo mochi-abt-io

cd chfs

echo PMEMKV backend
for hashing in " " --enable-modular-hashing
do
	for port in " " --enable-hash-port
	do
		for zero in " " --enable-zero-copy-read-rdma
		do
			echo ./configure --with-pmemkv $hashing $port $zero
			./configure --with-pmemkv $hashing $port $zero > /dev/null
			make clean > /dev/null
			make > /dev/null
		done
	done
done

echo POSIX backend
for hashing in " " --enable-modular-hashing
do
	for port in " " --enable-hash-port
	do
		for xattr in " " --enable-xattr
		do
			for abtio in " " --with-abt-io
			do
				echo ./configure $hashing $port $xattr $abtio
				./configure $hashing $port $xattr $abtio > /dev/null
				make clean > /dev/null
				make > /dev/null
			done
		done
	done
done
