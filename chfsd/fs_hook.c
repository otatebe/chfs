#include <stddef.h>
#include <time.h>
#include <abt.h>
#include "fs_hook.h"

static int rpc_count = 0;
static struct timespec rpc_wait_time;
static double rpc_last_interval = 1;
static ABT_mutex_memory mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory begin_cond_mem = ABT_COND_INITIALIZER;
static ABT_cond_memory end_cond_mem = ABT_COND_INITIALIZER;

void
fs_server_set_rpc_last_interval(double second)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	ABT_mutex_lock(mutex);
	rpc_last_interval = second;
	ABT_mutex_unlock(mutex);
}

double
fs_server_get_rpc_last_interval(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	double s;

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
	ABT_cond_broadcast(begin_cond);
	ABT_mutex_unlock(mutex);
}

#define NSEC	1000000000L

static void
timespec_add(struct timespec *t, double d)
{
	time_t d_sec = d;
	long d_nsec = (d - d_sec) * NSEC;

	t->tv_sec += d_sec;
	t->tv_nsec += d_nsec;
	if (t->tv_nsec >= NSEC) {
		t->tv_nsec -= NSEC;
		t->tv_sec++;
	} else if (t->tv_nsec < 0) {
		t->tv_nsec += NSEC;
		t->tv_sec--;
	}
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
		timespec_add(&rpc_wait_time, rpc_last_interval);
		ABT_cond_broadcast(end_cond);
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
