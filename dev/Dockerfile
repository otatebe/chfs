FROM ubuntu

ARG USERNAME=foo
ARG UID=1000

RUN apt-get update \
 && apt-get -y upgrade \
 && apt-get -y install \
    gcc automake \
    cmake libtool pkgconf \
    git python3 bison fuse sudo vim curl \
    libpmemkv-dev libmemkind-dev libtbb-dev \
    rapidjson-dev \
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

RUN useradd -m -u $UID -s /bin/bash $USERNAME \
 && echo "$USERNAME ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers.d/$USERNAME \
 # delete passwd
 && passwd -d $USERNAME

USER $USERNAME
RUN cd \
 && mkdir local \
 && git clone -c feature.manyFiles=true --depth 1 https://github.com/spack/spack.git \
 && . spack/share/spack/setup-env.sh \
# && git clone https://github.com/mochi-hpc/mochi-spack-packages.git \
# && spack repo add mochi-spack-packages \
 && spack external find automake autoconf libtool cmake m4 pkgconf bison \
 && spack install mochi-margo ^mercury~boostsys ^libfabric fabrics=rxm,sockets,tcp,udp \
# && spack install mochi-abt-io \
 && printf '%s\n' \
    'export LC_ALL=C' \
    '. $HOME/spack/share/spack/setup-env.sh' \
    'export PATH=$HOME/local/bin:$PATH' \
    'export LD_LIBRARY_PATH=$HOME/local/lib:$LD_LIBRARY_PATH' \
    'export PKG_CONFIG_PATH=$HOME/local/lib/pkgconfig:$PKG_CONFIG_PATH' \
    >> .bashrc
