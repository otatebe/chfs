#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <libgen.h>
#include <errno.h>
#include <margo.h>
#include "ring.h"
#include "ring_types.h"
#include "ring_rpc.h"
#include "ring_list.h"
#include "ring_list_rpc.h"
#include "kv_types.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "host.h"
#include "log.h"

void
ring_fatal(hg_return_t err, const char *diag)
{
	if (err == HG_SUCCESS)
		return;
	log_fatal("%s: %s, abort", diag, HG_Error_to_string(err));
}

void
join_ring(margo_instance_id mid, const char *server)
{
	hg_return_t ret;
	hg_addr_t addr;
	char addr_str[PATH_MAX];
	size_t addr_str_size = sizeof(addr_str);
	char *prev, *self;

	margo_addr_lookup(mid, server, &addr);
	margo_addr_to_string(mid, addr_str, &addr_str_size, addr);
	margo_addr_free(mid, addr);
	ring_set_next(addr_str);
	self = ring_get_self();
	ret = ring_rpc_join(addr_str, self, &prev);
	ring_release_self();
	ring_fatal(ret, "join");
	assert(prev != NULL);
	ring_set_prev(prev);
	free(prev);
}

static void
leave()
{
	char *next, *prev;
	int prev_prev = 0;
	hg_return_t ret;

	next = ring_get_next();
	prev = ring_get_prev();
	ret = ring_rpc_set_next(prev, next);
	if (ret != HG_SUCCESS) {
		prev = ring_get_prev_prev();
		ring_rpc_set_next(prev, next);
		prev_prev = 1;
	}
	ret = ring_rpc_set_prev(next, prev);
	if (ret != HG_SUCCESS) {
		next = ring_get_next_next();
		ring_rpc_set_prev(next, prev);
		ring_rpc_set_next(prev, next);
		ring_release_next_next();
	}
	ring_release_prev();
	if (prev_prev == 1)
		ring_release_prev_prev();
	ring_release_next();
	fs_server_term();
	log_term();
}

void *
handle_sig(void *arg)
{
	sigset_t *a = arg;
	int sig;

	sigwait(a, &sig);
	leave();
	exit(1);
}

void
usage(char *prog_name)
{
	fprintf(stderr, "Usage: %s [-d] [-c db_dir] [-p protocol] [-h host] "
		"[-l log_file]\n\t[-S server_info_file] [-t rpc_timeout_msec] "
		"[server]\n", prog_name);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char addr_str[PATH_MAX], *host_addr;
	size_t addr_str_size = sizeof(addr_str);
	hg_addr_t my_address;
	pthread_t t;
	static sigset_t sigset;
	margo_instance_id mid;
	char *db_dir = "/tmp", *hostname = NULL, *log_file = NULL;
	char *protocol = "sockets", info_string[PATH_MAX];
	char *server_info_file = NULL;
	int opt, debug = 0, rpc_timeout_msec = 10000;
	char *prog_name;

	prog_name = basename(argv[0]);

	while ((opt = getopt(argc, argv, "c:dh:l:p:S:t:")) != -1) {
		switch (opt) {
		case 'c':
			db_dir = optarg;
			break;
		case 'd':
			debug = 1;
			log_set_priority_max_level(LOG_DEBUG);
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'p':
			protocol = optarg;
			break;
		case 'S':
			server_info_file = optarg;
			break;
		case 't':
			rpc_timeout_msec = atoi(optarg);
			break;
		default:
			usage(prog_name);
		}
	}
	argc -= optind;
	argv += optind;

	if (!debug) {
		if (log_file)
			log_file_open(log_file);
		else
			log_syslog_open(prog_name, LOG_PID, LOG_LOCAL0);
		if (daemon(1, 0) == -1)
			log_fatal("daemon");
	}

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	pthread_create(&t, NULL, handle_sig, &sigset);
	pthread_detach(t);

	/* XXX - should check the validity of input string */
	sprintf(info_string, "%s", protocol);
	if (hostname != NULL) {
		strcat(info_string, "://");
		host_addr = host_getaddr(hostname);
		if (host_addr == NULL)
			strcat(info_string, hostname);
		else {
			strcat(info_string, host_addr);
			free(host_addr);
		}
	}
	log_info("information string %s", info_string);
	mid = margo_init(info_string, MARGO_SERVER_MODE, 1, 5);
	if (mid == MARGO_INSTANCE_NULL)
		log_fatal("margo_init failed, abort");

	margo_addr_self(mid, &my_address);
	margo_addr_to_string(mid, addr_str, &addr_str_size, my_address);
	margo_addr_free(mid, my_address);
	log_info("Server running at address %s", addr_str);
	if (server_info_file) {
		FILE *fp = fopen(server_info_file, "w");

		if (fp) {
			fprintf(fp, "%s\n", addr_str);
			fclose(fp);
		} else
			log_error("%s: %s", server_info_file, strerror(errno));
	}

	ring_init(addr_str);
	ring_list_init(addr_str);
	ring_rpc_init(mid, rpc_timeout_msec);
	ring_list_rpc_init(mid, rpc_timeout_msec);
	fs_server_init(mid, db_dir, rpc_timeout_msec);

	if (argc > 0)
		join_ring(mid, argv[0]);
#if 0
	while (1) {
		if (ring_list_is_coordinator(addr_str)) {
			puts("coordinator");
			ring_heartbeat();
		} else if (ring_heartbeat_is_timeout())
			ring_start_election();
		sleep(1);
	}
#endif
	margo_wait_for_finalize(mid);

	return (0);
}
