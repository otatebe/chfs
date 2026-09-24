#!/bin/sh

echo c1
cat log/*

for h in $(cat hosts)
do
	[ $h = c1 ] && continue
	echo $h
	ssh $h cat log/\*
done
