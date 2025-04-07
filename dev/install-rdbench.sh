#!/bin/sh

echo Install RDBench
set -eux

cd
[ -d rdbench ] || git clone https://github.com/range3/rdbench.git
cd rdbench
git pull > /dev/null || :

[ -d vcpkg ] || git clone https://github.com/microsoft/vcpkg.git

cmake -B build -D CMAKE_BUILD_TYPE=Release -D CMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake -D CMAKE_MODULE_PATH=cmake/fetch_content -DCMAKE_INSTALL_PREFIX=$HOME/local
cmake --build build > /dev/null
cmake --install build > /dev/null

echo Install RDBench viz

ENVDIR=~/local/rdbench-venv
[ -d $ENVDIR ] || {
	python3 -m venv $ENVDIR
	. $ENVDIR/bin/activate
	pip install -U pip
	pip install matplotlib
	deactivate
}
