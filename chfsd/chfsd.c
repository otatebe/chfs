#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
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
#include "file.h"
#include "log.h"

static char *self;

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
	char *prev;

	ret = margo_addr_lookup(mid, server, &addr);
	ring_fatal(ret, "join:lookup");
	margo_addr_to_string(mid, addr_str, &addr_str_size, addr);
	margo_addr_free(mid, addr);
	ring_set_next(addr_str);
	ret = ring_rpc_join(addr_str, &prev);
	ring_fatal(ret, "join:rpc_join");
	ring_set_prev(prev);
	free(prev);
}

static void
leave()
{
	char *next, *prev;
	int prev_prev = 0;
	hg_return_t ret;

	log_debug("leave");
	next = ring_get_next();
	if (strcmp(self, next) == 0)
		goto leave;
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
leave:
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

static void
check_directory(char *dir)
{
	struct stat sb;
	int r;

	r = stat(dir, &sb);
	if (r == -1) {
		if (errno != ENOENT)
			log_fatal("%s: %s", dir, strerror(errno));
		r = mkdir_p(dir, 0755);
		if (r == -1)
			log_fatal("%s: %s", dir, strerror(errno));
		log_info("%s: created", dir);
	} else if (!S_ISDIR(sb.st_mode))
		log_fatal("%s: not a directory", dir);
	return;
}

void
usage(char *prog_name)
{
	fprintf(stderr, "Usage: %s [-d] [-c db_dir] [-s db_size] "
		"[-p protocol] [-n name]\n\t[-h host[:port]/device] "
		"[-l log_file] [-S server_info_file]\n\t[-t rpc_timeout_msec] "
		"[-T nthreads] [-H heartbeat_interval]\n\t[-L log_priority] "
		"[server]\n", prog_name);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	char addr_str[PATH_MAX], *host_addr;
	size_t addr_str_size = sizeof(addr_str), db_size = 256 * 1024 * 1024;
	hg_addr_t my_address;
	pthread_t t;
	static sigset_t sigset;
	margo_instance_id mid;
	char *db_dir = "/tmp", *hostname = NULL, *log_file = NULL;
	char *protocol = "sockets", info_string[PATH_MAX];
	char *server_info_file = NULL, *virtual_name = NULL;
	int opt, debug = 0, rpc_timeout_msec = 0, nthreads = 5;
	int heartbeat_interval = 10, log_priority = -1;
	char *prog_name;

	prog_name = basename(argv[0]);

	while ((opt = getopt(argc, argv, "c:dh:H:l:L:n:p:s:S:t:T:")) != -1) {
		switch (opt) {
		case 'c':
			db_dir = optarg;
			break;
		case 'd':
			debug = 1;
			if (log_priority == -1)
				log_priority = LOG_DEBUG;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'H':
			heartbeat_interval = atoi(optarg);
			break;
		case 'l':
			log_file = optarg;
			break;
		case 'L':
			log_priority = log_priority_from_name(optarg);
			if (log_priority == -1)
				log_error("%s: invalid log priority", optarg);
			break;
		case 'n':
			virtual_name = optarg;
			break;
		case 'p':
			protocol = optarg;
			break;
		case 's':
			db_size = atol(optarg);
			break;
		case 'S':
			server_info_file = optarg;
			break;
		case 't':
			rpc_timeout_msec = atoi(optarg);
			break;
		case 'T':
			nthreads = atoi(optarg);
			break;
		default:
			usage(prog_name);
		}
	}
	if (log_priority != -1)
		log_set_priority_max_level(log_priority);
	argc -= optind;
	argv += optind;

	check_directory(db_dir);
	if (!debug) {
		if (log_file) {
			if (log_file_open(log_file) == -1)
				log_fatal("%s: %s", log_file, strerror(errno));
		} else
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
	mid = margo_init(info_string, MARGO_SERVER_MODE, 1, nthreads);
	if (mid == MARGO_INSTANCE_NULL)
		log_fatal("margo_init failed, abort");

	margo_addr_self(mid, &my_address);
	margo_addr_to_string(mid, addr_str, &addr_str_size, my_address);
	margo_addr_free(mid, my_address);
	log_info("Server running at address %s", addr_str);

	ring_init(addr_str, virtual_name);
	self = ring_get_self();
	ring_list_init(addr_str);
	ring_rpc_init(mid, rpc_timeout_msec);
	ring_list_rpc_init(mid, rpc_timeout_msec);

	if (server_info_file) {
		FILE *fp = fopen(server_info_file, "w");

		if (fp) {
			fprintf(fp, "%s\n", addr_str);
			fclose(fp);
		} else
			log_error("%s: %s", server_info_file, strerror(errno));
	}

	fs_server_init(mid, db_dir, db_size, rpc_timeout_msec);

	ring_set_heartbeat_timeout(heartbeat_interval * 10);
	log_debug("heartbeat interval: %d (timeout %d)",
		heartbeat_interval, heartbeat_interval * 10);

	if (argc > 0) {
		join_ring(mid, argv[0]);
		ring_wait_coordinator_rpc();
	}
	while (heartbeat_interval > 0) {
		if (ring_list_is_coordinator(addr_str)) {
			log_debug("coordinator");
			ring_heartbeat();
		} else if (ring_heartbeat_is_timeout())
			ring_start_election();
		sleep(heartbeat_interval);
	}
	margo_wait_for_finalize(mid);

	return (0);
}
