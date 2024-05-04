FROM ubuntu

ARG USERNAME=foo
ARG UID=1000

RUN apt-get update \
 && apt-get -y upgrade \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install \
    gcc g++ automake \
    cmake libtool pkgconf \
    libpmemobj-dev libmemkind-dev libtbb-dev rapidjson-dev \
    libjson-c-dev libboost-dev \
    git fuse sudo vim curl wget \
    libfuse-dev pandoc \
    libopenmpi-dev libssl-dev \
    gdb numactl

RUN \
  # sshd
  apt-get -y install --no-install-recommends \
    openssh-server \
  # sshd_config
  && printf '%s\n' \
    'PasswordAuthentication yes' \
    'PermitEmptyPasswords yes' \
    'UsePAM no' \
    > /etc/ssh/sshd_config.d/auth.conf \
  # ssh_config
  && printf '%s\n' \
    'Host *' \
    '    StrictHostKeyChecking no' \
    > /etc/ssh/ssh_config.d/ignore-host-key.conf

RUN id $UID && userdel $(id -un $UID) || : \
 && useradd -m -u $UID -s /bin/bash $USERNAME \
 && echo "$USERNAME ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers.d/$USERNAME \
 # delete passwd
 && passwd -d $USERNAME

RUN cd \
 && git clone https://github.com/pmem/libpmemobj-cpp.git \
 && cd libpmemobj-cpp \
 && mkdir build && cd build \
 && cmake -DTESTS_USE_VALGRIND:BOOL=OFF .. \
 && make -j $(nproc) && make install \
 && ldconfig

RUN cd \
 && git clone https://github.com/pmem/pmemkv.git \
 && cd pmemkv \
 && printf '%s\n' \
    '--- a/src/libpmemkv.hpp' \
    '+++ b/src/libpmemkv.hpp' \
    '@@ -13,6 +13,7 @@' \
    ' #include <stdexcept>' \
    ' #include <string>' \
    ' #include <utility>' \
    '+#include <cstdint>' \
    '' \
    ' #include "libpmemkv.h"' \
    ' #include <libpmemobj/pool_base.h>' \
    | patch -p1 \
 && mkdir build && cd build \
 && cmake -DBUILD_TESTS:BOOL=OFF .. \
 && make -j $(nproc) && make install \
 && ldconfig

ARG LIBFABRIC_VER=1.21.0

RUN cd \
 && wget https://github.com/ofiwg/libfabric/archive/refs/tags/v$LIBFABRIC_VER.tar.gz \
 && tar zxfp v$LIBFABRIC_VER.tar.gz \
 &&  cd libfabric-$LIBFABRIC_VER \
 && ./autogen.sh \
 && mkdir build && cd build \
 && ../configure \
 && make -j $(nproc) && make install \
 && ldconfig

ARG MERCURY_VER=2.3.1

RUN cd \
 && wget https://github.com/mercury-hpc/mercury/archive/refs/tags/v$MERCURY_VER.tar.gz \
 && tar zxfp v$MERCURY_VER.tar.gz \
 && cd mercury-$MERCURY_VER \
 && mkdir build && cd build \
 && cmake -DNA_USE_OFI:BOOL=ON -DMERCURY_USE_BOOST_PP:BOOL=ON -DBUILD_SHARED_LIBS:BOOL=ON -DCMAKE_BUILD_TYPE:STRING=Debug .. \
 && make -j $(nproc) && make install \
 && ldconfig

ARG ARGOBOTS_VER=1.2

RUN cd \
 && wget https://github.com/pmodels/argobots/releases/download/v$ARGOBOTS_VER/argobots-$ARGOBOTS_VER.tar.gz \
 && tar zxfp argobots-$ARGOBOTS_VER.tar.gz \
 && cd argobots-$ARGOBOTS_VER \
 && mkdir build && cd build \
 && ../configure \
 && make -j $(nproc) && make install \
 && ldconfig

ARG MARGO_VER=0.16.0

RUN cd \
 && wget https://github.com/mochi-hpc/mochi-margo/archive/refs/tags/v$MARGO_VER.tar.gz \
 && tar zxfp v$MARGO_VER.tar.gz \
 && cd mochi-margo-$MARGO_VER \
 && ./prepare.sh \
 && mkdir build && cd build \
 && ../configure \
 && make -j $(nproc) && make install \
 && ldconfig

USER $USERNAME
RUN cd \
 && mkdir local \
 && printf '%s\n' \
    'export LC_ALL=C' \
    'export PATH=$HOME/local/bin:$PATH' \
    'export LD_LIBRARY_PATH=$HOME/local/lib:$LD_LIBRARY_PATH' \
    'export PKG_CONFIG_PATH=$HOME/local/lib/pkgconfig:$PKG_CONFIG_PATH' \
    >> .bashrc
