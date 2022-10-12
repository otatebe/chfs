#!/bin/sh

set -e

. $HOME/spack/share/spack/setup-env.sh
spack load mochi-margo #mochi-abt-io

cd $HOME/chfs

echo PMEMKV backend
for hashing in " " --enable-modular-hashing
do
	for port in " " --enable-hash-port
	do
		for zero in " " --enable-zero-copy-read-rdma
		do
			for md5 in " " --enable-digest-md5
			do
				echo ./configure --with-pmemkv \
					$hashing $port $zero $md5
				./configure --with-pmemkv \
					$hashing $port $zero $md5 > /dev/null
				make clean > /dev/null
				make > /dev/null
			done
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
#			for abtio in " " --with-abt-io
#			do
				for md5 in " " --enable-digest-md5
				do
					echo ./configure $hashing $port \
						$xattr $abtio $md5
					./configure $hashing $port \
						$xattr $abtio $md5 > /dev/null
					make clean > /dev/null
					make > /dev/null
				done
#			done
		done
	done
done
