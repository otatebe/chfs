TERM_INHERIT = $${TERM+--env TERM='${TERM}'}

login:
	docker exec -u ${USER} $(TERM_INHERIT) \
		-w /home/${USER}/chfs/dev -it chfs-c1 /bin/bash

build:
	docker compose build --build-arg UID=$(shell id -u)

up:
	docker compose up -d

down:
	docker compose down
