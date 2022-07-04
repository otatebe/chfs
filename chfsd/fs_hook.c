#include <stddef.h>
#include <time.h>
#include <abt.h>
#include "fs_hook.h"

static int rpc_count = 0;
static struct timespec rpc_wait_time;
static int rpc_last_interval = 5;
static ABT_mutex_memory mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory begin_cond_mem = ABT_COND_INITIALIZER;
static ABT_cond_memory end_cond_mem = ABT_COND_INITIALIZER;

void
fs_server_set_rpc_last_interval(int second)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	ABT_mutex_lock(mutex);
	rpc_last_interval = second;
	ABT_mutex_unlock(mutex);
}

int
fs_server_get_rpc_last_interval(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	int s;

	ABT_mutex_lock(mutex);
	s = rpc_last_interval;
	ABT_mutex_unlock(mutex);
	return (s);
}

/* internal function */
static int
rpc_last_interval_past()
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (ts.tv_sec > rpc_wait_time.tv_sec
		|| (ts.tv_sec == rpc_wait_time.tv_sec
		    && ts.tv_nsec >= rpc_wait_time.tv_nsec));
}

void
fs_server_rpc_begin(void *func, const char *diag)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond begin_cond = ABT_COND_MEMORY_GET_HANDLE(&begin_cond_mem);

	ABT_mutex_lock(mutex);
	++rpc_count;
	ABT_cond_signal(begin_cond);
	ABT_mutex_unlock(mutex);
}

void
fs_server_rpc_end(void *func, const char *diag)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond end_cond = ABT_COND_MEMORY_GET_HANDLE(&end_cond_mem);

	ABT_mutex_lock(mutex);
	--rpc_count;
	if (rpc_count <= 0) {
		clock_gettime(CLOCK_REALTIME, &rpc_wait_time);
		rpc_wait_time.tv_sec += rpc_last_interval;
		ABT_cond_signal(end_cond);
	}
	ABT_mutex_unlock(mutex);
}

void
fs_server_rpc_wait(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond begin_cond = ABT_COND_MEMORY_GET_HANDLE(&begin_cond_mem);
	ABT_cond end_cond = ABT_COND_MEMORY_GET_HANDLE(&end_cond_mem);
	struct timespec ts;

	ABT_mutex_lock(mutex);
	while (rpc_count > 0 || !rpc_last_interval_past()) {
		if (rpc_count > 0)
			ABT_cond_wait(end_cond, mutex);

		ts = rpc_wait_time;
		if (!rpc_last_interval_past())
			ABT_cond_timedwait(begin_cond, mutex, &ts);
	}
	ABT_mutex_unlock(mutex);
}
