FROM ubuntu

ARG USERNAME=foo

RUN apt-get update \
 && apt-get -y upgrade \
 && apt-get -y install build-essential \
 && apt-get -y install cmake libtool pkgconf \
 && apt-get -y install git python3 fuse sudo vim curl \
 && apt-get -y install libpmemkv-dev libmemkind-dev libtbb-dev \
 && apt-get -y install rapidjson-dev \
 && apt-get -y install libfuse-dev pandoc \
 && apt-get -y install libopenmpi-dev libssl-dev

RUN \
  # sshd
  apt-get -y install --no-install-recommends \
    openssh-server \
  # sshd_config
  && printf '%s\n' \
    'PermitRootLogin yes' \
    'PasswordAuthentication yes' \
    'PermitEmptyPasswords yes' \
    'UsePAM no' \
    > /etc/ssh/sshd_config.d/auth.conf \
  # ssh_config
  && printf '%s\n' \
    'Host *' \
    '    StrictHostKeyChecking no' \
    > /etc/ssh/ssh_config.d/ignore-host-key.conf

RUN useradd -m -s /bin/bash $USERNAME \
 && echo "$USERNAME ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers.d/$USERNAME \
 # delete passwd
 && passwd -d $USERNAME

USER $USERNAME
RUN cd \
 && git clone -c feature.manyFiles=true --depth 1 https://github.com/spack/spack.git \
 && . spack/share/spack/setup-env.sh \
 && git clone https://github.com/mochi-hpc/mochi-spack-packages.git \
 && spack repo add mochi-spack-packages \
 && spack external find automake autoconf libtool cmake m4 pkgconf \
 && spack install mochi-margo ^mercury~boostsys ^libfabric fabrics=rxm,sockets,tcp,udp \
 && spack install mochi-abt-io \
 && echo ". spack/share/spack/setup-env.sh" >> .bashrc

COPY --chown=$USERNAME:$USERNAME . /home/$USERNAME/chfs
COPY --chown=$USERNAME:$USERNAME dev/hosts /home/$USERNAME/hosts

RUN cd \
 && . spack/share/spack/setup-env.sh \
 && spack load mochi-margo mochi-abt-io \
 && cd chfs \
 && autoreconf -i \
 && ./configure \
 && make \
 && sudo make install \
 && sudo ldconfig \
 && make clean

#COPY --chown=$USERNAME:$USERNAME ior /home/$USERNAME/ior

RUN cd \
 && . spack/share/spack/setup-env.sh \
 && spack load mochi-margo \
 && git clone https://github.com/otatebe/ior.git -b feature/chfs \
 && cd ior \
 && ./bootstrap \
 && ./configure \
 && make \
 && sudo make install \
 && make clean

COPY --chown=$USERNAME:$USERNAME dev/test.sh /home/$USERNAME/test.sh
