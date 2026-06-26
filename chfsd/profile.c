#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <abt.h>
#include "key.h"
#include "log.h"

#include "profile.h"

#define X(a) #a,
static char *profile_op_list[] = { PROFILE_OP };
#undef X

static int profile_enabled = 0;

void
profile_enable(int enable)
{
	profile_enabled = enable;
}

static char *
profile_op_string(int op)
{
	if (op < 0 || op > PROF_OP_UNKNOWN)
		op = PROF_OP_UNKNOWN;
	return (profile_op_list[op]);
}

void
profile_gettime(struct timespec *ts)
{
	if (!profile_enabled)
		return;
	clock_gettime(CLOCK_REALTIME, ts);
}

struct entry {
	struct entry *next;
	struct timespec ts1, ts2;
	void *key;
	size_t key_size, value_size;
	size_t off;
	int op;
};

static ABT_mutex_memory mutex_mem = ABT_MUTEX_INITIALIZER;

static struct profile_list {
	struct entry *head;
	struct entry **tail;
} profile_list = {
	NULL, &profile_list.head
};

static void
profile_entry_free(struct entry *e)
{
	free(e->key);
	free(e);
}

int
profile_enq(int op, void *key, size_t key_size, size_t value_size, size_t off,
	struct timespec *ts1, struct timespec *ts2)
{
	struct entry *e;
	int index = key_index(key, key_size);
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	static const char diag[] = "profile_enq";

	if (!profile_enabled)
		return (0);

	log_debug("%s: %s %s:%d %ld", diag, profile_op_string(op),
		(char *)key, index, value_size);
	e = malloc(sizeof *e);
	if (e == NULL) {
		log_error("%s: %s %s:%d %ld: no memory", diag,
			profile_op_string(op), (char *)key, index, value_size);
		return (1);
	}
	e->next = NULL;
	e->key = malloc(key_size);
	if (e->key == NULL) {
		log_error("%s: %s %s:%d %ld: no memory", diag,
			profile_op_string(op), (char *)key, index, value_size);
		free(e);
		return (1);
	}
	memcpy(e->key, key, key_size);
	e->key_size = key_size;
	e->value_size = value_size;
	e->off = off;
	e->op = op;
	e->ts1 = *ts1;
	e->ts2 = *ts2;

	ABT_mutex_lock(mutex);
	*profile_list.tail = e;
	profile_list.tail = &e->next;
	ABT_mutex_unlock(mutex);

	return (0);
}

static struct entry *
profile_deq(void)
{
	struct entry *e = NULL;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	if (!profile_enabled)
		return (NULL);

	ABT_mutex_lock(mutex);
	if (profile_list.head == NULL)
		goto unlock;

	if (profile_list.head) {
		e = profile_list.head;
		profile_list.head = e->next;
	}
	if (profile_list.head == NULL)
		profile_list.tail = &profile_list.head;
unlock:
	ABT_mutex_unlock(mutex);

	return (e);
}

static void
profile_display(struct entry *e)
{
	int index = key_index(e->key, e->key_size);

	log_notice("%s %s:%d %ld %ld %ld %ld %ld %ld", profile_op_string(e->op),
		(char *)e->key, index, e->value_size, e->off,
		e->ts1.tv_sec, e->ts1.tv_nsec, e->ts2.tv_sec, e->ts2.tv_nsec);
}

void
profile_dump(void)
{
	struct entry *e;

	if (!profile_enabled)
		return;

	while ((e = profile_deq())) {
		profile_display(e);
		profile_entry_free(e);
	}
}
