# Docker containers for developers

## How to use

- build image

      $ docker compose build

  This creates a docker image using the current source files of CHFS.  For details, see Dockerfile.

- execute containers

      $ docker compose up -d

  This executes four contaiers using the docker image.  You can login to all containers by ssh.  For details, see docker-compose.yml.

- login to a container

      $ ssh 172.30.0.2

- execute a test script (in a container)

      c1$ sh test.sh

- explore CHFS (in a container)

      c1$ eval $(chfsctl -h hosts -m /tmp/a start)
      c1$ chlist

- IOR (in a container)

      c1$ mpirun -hostfile hosts -x PATH -x LD_LIBRARY_PATH -x CHFS_SERVER ior -a CHFS --chfs.chunk_size=1048576 -o /tmp/a/testfile

- stop CHFS (in a container)

      c1$ chfsctl -h hosts -m /tmp/a stop

- shutdown containers

      $ docker compose down
