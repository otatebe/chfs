# Docker containers for developers

## Prerequisite

- install `docker compose` ([Ubuntu](https://docs.docker.com/engine/install/ubuntu/) | [CentOS](https://docs.docker.com/engine/install/centos/)) and `make`.

- to allow docker compose to run with user privileges, add $USER to the docker group by `sudo usermod -aG docker $USER`

## How to use

- build image

      $ make build

  This creates a docker image to build CHFS.  For details, see Dockerfile.

- execute containers

      $ make up

  This executes four contaiers using the docker image.  You can login to all containers by ssh.  For details, see docker-compose.yml.

- login to a container

      $ make

- install CHFS, MPI and IOR (in a container)

      c1$ sh install.sh

- execute a test script (in a container)

      c1$ sh test.sh

- explore CHFS (in a container)

      c1$ eval $(chfsctl -h hosts -m /tmp/a -b $PWD/backend -L log start)
      c1$ chlist

- execute IOR (in a container)

      c1$ mpirun -hostfile hosts -x PATH -x CHFS_SERVER -x CHFS_BACKEND_PATH -x CHFS_SUBDIR_PATH ior -a CHFS --chfs.chunk_size=1048576 -o /tmp/a/testfile

- stop CHFS (in a container)

      c1$ chfsctl -h hosts -m /tmp/a stop

- shutdown containers (in a host)

      $ make down

- shutdown containers and remove volumes (in a host)

      $ make down-volume

  This removes the volume for `~/local`.  Next time, install everything again by `sh install.sh`.

- shutdown containers and remove volumes and the docker image (in a host)

      $ make clean

  Next time, start from `make build`.
