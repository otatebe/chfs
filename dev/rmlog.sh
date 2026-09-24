#!/bin/sh

echo c1
rm log/*

for h in $(cat hosts)
do
	[ $h = c1 ] && continue
	echo $h
	ssh $h rm log/\*
done
