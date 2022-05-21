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
#include "config.h"
#include "path.h"
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
#include "flush.h"
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
move_all_data()
{
	inode_copy_all();
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
	if (strcmp(self, prev) == 0)
		goto leave_prev;
	ret = ring_rpc_set_next(prev, next);
	if (ret != HG_SUCCESS) {
		prev = ring_get_prev_prev();
		prev_prev = 1;
		if (strcmp(self, prev) == 0)
			goto leave_prev;
		ret = ring_rpc_set_next(prev, next);
		if (ret != HG_SUCCESS)
			log_error("leave (set_next): %s",
					HG_Error_to_string(ret));
	}
	ret = ring_rpc_set_prev(next, prev);
	if (ret != HG_SUCCESS) {
		next = ring_get_next_next();
		if (strcmp(self, next)) {
			ret = ring_rpc_set_prev(next, prev);
			if (ret != HG_SUCCESS)
				log_error("leave (set_prev): %s",
						HG_Error_to_string(ret));
			ret = ring_rpc_set_next(prev, next);
			if (ret != HG_SUCCESS)
				log_error("leave (set_next): %s",
						HG_Error_to_string(ret));
		}
		ring_release_next_next();
	}
	ring_list_remove(self);
	log_debug("move_all_data");
	if (ret == HG_SUCCESS)
		move_all_data();
	log_debug("move_all_data: done");
leave_prev:
	ring_release_prev();
	if (prev_prev == 1)
		ring_release_prev_prev();
leave:
	ring_release_next();
	log_debug("flush_wait");
	fs_inode_flush_wait();
	log_debug("flush_wait: done");
	fs_server_term();
	log_term();
}

static int heartbeat_stop = 0;
static int heartbeat_done = 0;
static ABT_mutex_memory hb_mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory hb_stop_cond_mem = ABT_COND_INITIALIZER;
static ABT_cond_memory hb_done_cond_mem = ABT_COND_INITIALIZER;

void *
handle_sig(void *arg)
{
	sigset_t *a = arg;
	int sig;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&hb_mutex_mem);
	ABT_cond stop_cond = ABT_COND_MEMORY_GET_HANDLE(&hb_stop_cond_mem);
	ABT_cond done_cond = ABT_COND_MEMORY_GET_HANDLE(&hb_done_cond_mem);

	sigwait(a, &sig);
	ABT_mutex_lock(mutex);
	heartbeat_stop = 1;
	ABT_mutex_unlock(mutex);
	ABT_cond_signal(stop_cond);
	ABT_mutex_lock(mutex);
	while (!heartbeat_done)
		ABT_cond_wait(done_cond, mutex);
	ABT_mutex_unlock(mutex);
	leave();
	return (NULL);
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
		r = fs_mkdir_p(dir, 0755);
		if (r == -1)
			log_fatal("%s: %s", dir, strerror(errno));
		log_info("%s: created", dir);
	} else if (!S_ISDIR(sb.st_mode) && !S_ISCHR(sb.st_mode))
		log_fatal("%s: not a directory or a character device", dir);
	return;
}

static char *
skip_space(char *s)
{
	while (*s == ' ')
		++s;
	return (s);
}

static char *
address_name_dup(char *address, char *name)
{
	int addrlen, namelen;
	char *r;

	if (address == NULL)
		return (NULL);
	addrlen = strlen(address);
	if (name != NULL)
		namelen = strlen(name);
	else
		namelen = 0;
#ifndef ENABLE_HASH_PORT
	int s = addrlen - 1;
	while (s >= 0 && address[s] != ':')
		--s;
	if (s >= 0 && address[s] == ':')
		addrlen = s;
#endif
	r = malloc(addrlen + 1 + namelen + 1);
	if (r == NULL)
		return (r);
	memcpy(r, address, addrlen);
	r[addrlen++] = ':';
	if (namelen > 0)
		strcpy(r + addrlen, name);
	else
		r[addrlen] = '\0';
	return (r);
}

static void
write_pid(char *file)
{
	FILE *f;
	static const char diag[] = "write_pid";

	if (file == NULL)
		return;

	f = fopen(file, "w");
	if (f == NULL)
		log_fatal("%s (open): %s: %s", diag, file, strerror(errno));
	if (fprintf(f, "%d\n", getpid()) < 0)
		log_error("%s (write): %s: %s", diag, file, strerror(errno));
	if (fclose(f))
		log_error("%s (close): %s: %s", diag, file, strerror(errno));
}

void
usage(char *prog_name)
{
	fprintf(stderr, "Usage: %s [-d] [-f] [-c db_dir] [-s db_size] "
		"[-b backend_dir]\n\t[-B subdir] [-f num_flush_threads] "
		"[-p protocol]\n\t[-h host[:port]/device] "
		"[-n vname] [-N virtual_name] [-P pid_file]\n\t[-l log_file] "
		"[-S server_info_file] [-t rpc_timeout_msec] "
		"[-T nthreads]\n\t[-I niothreads] [-H heartbeat_interval] "
		"[-L log_priority] [server]\n", prog_name);
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
	char *server_info_file = NULL, *vname = NULL, *virtual_name = NULL;
	char *addr_name = NULL, *backend_dir = NULL, *subdir = NULL;
	int opt, foreground = 0, rpc_timeout_msec = 0, nthreads = 5;
	int heartbeat_interval = 10, log_priority = -1, niothreads = 2;
	int nflushthreads = 1;
	char *prog_name, *pid_file = NULL;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&hb_mutex_mem);
	ABT_cond stop_cond = ABT_COND_MEMORY_GET_HANDLE(&hb_stop_cond_mem);
	ABT_cond done_cond = ABT_COND_MEMORY_GET_HANDLE(&hb_done_cond_mem);

	prog_name = basename(argv[0]);

	while ((opt = getopt(argc, argv,
			"b:B:c:dfF:h:H:I:l:L:n:N:p:P:s:S:t:T:")) != -1) {
		switch (opt) {
		case 'b':
			backend_dir = optarg;
			break;
		case 'B':
			subdir = optarg;
			break;
		case 'c':
			db_dir = optarg;
			break;
		case 'd':
			foreground = 1;
			if (log_priority == -1)
				log_priority = LOG_DEBUG;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'F':
			nflushthreads = atoi(optarg);
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'H':
			heartbeat_interval = atoi(optarg);
			break;
		case 'I':
			niothreads = atoi(optarg);
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
			vname = optarg;
			break;
		case 'N':
			virtual_name = optarg;
			break;
		case 'p':
			protocol = optarg;
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 's':
			db_size = atol(optarg);
			break;
		case 'S':
			server_info_file = skip_space(optarg);
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

	log_info("CHFS version %s", VERSION);

	check_directory(db_dir);
	if (backend_dir) {
		check_directory(backend_dir);
		path_set_backend_path(backend_dir);
	}
	if (subdir)
		path_set_subdir_path(subdir);

	if (log_file) {
		if (log_file_open(log_file) == -1)
			log_fatal("%s: %s", log_file, strerror(errno));
	} else if (!foreground)
		log_syslog_open(prog_name, LOG_PID, LOG_LOCAL0);
	if (!foreground) {
		if (daemon(1, 0) == -1)
			log_fatal("daemon");
	}
	write_pid(pid_file);

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	pthread_create(&t, NULL, handle_sig, &sigset);
	pthread_detach(t);

	fs_inode_flush_thread_start(nflushthreads);

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

	if (virtual_name == NULL)
		virtual_name = addr_name = address_name_dup(addr_str, vname);
	ring_init(addr_str, virtual_name);
	ring_list_init(addr_str, virtual_name);
	free(addr_name);
	self = ring_get_self();
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

	fs_server_init(mid, db_dir, db_size, rpc_timeout_msec, niothreads);

	ring_set_heartbeat_timeout(heartbeat_interval * 10);
	log_debug("heartbeat interval: %d (timeout %d)",
		heartbeat_interval, heartbeat_interval * 10);

	if (argc > 0) {
		join_ring(mid, argv[0]);
		ring_wait_coordinator_rpc();
	}
	while (heartbeat_interval > 0) {
		struct timespec ts;
		int ret = ABT_SUCCESS, stop;

		if (ring_list_is_coordinator(addr_str)) {
			log_debug("coordinator");
			ring_heartbeat();
		} else if (ring_heartbeat_is_timeout())
			ring_start_election();
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += heartbeat_interval;
		ABT_mutex_lock(mutex);
		while (!heartbeat_stop && ret != ABT_ERR_COND_TIMEDOUT)
			ret = ABT_cond_timedwait(stop_cond, mutex, &ts);
		stop = heartbeat_stop;
		ABT_mutex_unlock(mutex);
		if (stop)
			break;
	}
	ABT_mutex_lock(mutex);
	heartbeat_done = 1;
	ABT_mutex_unlock(mutex);
	ABT_cond_signal(done_cond);
	margo_wait_for_finalize(mid);

	return (0);
}
