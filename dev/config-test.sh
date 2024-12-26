#!/bin/sh

set -e

echo PMEMKV backend
for hashing in " " --disable-modular-hashing
do
	for port in " " --enable-hash-port
	do
		for zero in " " --enable-zero-copy-read-rdma
		do
# md5 segfaults with zpoline
#			for md5 in " " --enable-digest-md5 \
			for md5 in " " \
				--enable-digest-murmur3
			do
				echo ./configure --with-pmemkv \
					$hashing $port $zero $md5
				sh ./install-chfs.sh --with-pmemkv \
					$hashing $port $zero $md5
				sh ./install-zpoline.sh
				sh ./test.sh
			done
		done
	done
done

echo POSIX backend
for hashing in " " --disable-modular-hashing
do
	for port in " " --enable-hash-port
	do
		for xattr in " " --enable-xattr
		do
#			for abtio in " " --with-abt-io
#			do
# md5 segfaults with zpoline
#				for md5 in " " --enable-digest-md5 \
				for md5 in " " \
					--enable-digest-murmur3
				do
					echo ./configure $hashing $port \
						$xattr $abtio $md5
					sh ./install-chfs.sh \
						$hashing $port \
						$xattr $abtio $md5
					sh ./install-zpoline.sh
					sh ./test.sh
				done
#			done
		done
	done
done
