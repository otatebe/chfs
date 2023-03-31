#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <abt.h>
#include "fs_hook.h"
#include "fs.h"
#include "log.h"

static int num_threads = 0;
static int stop_requested = 0;
static int num_stopped_threads = 0;

struct entry {
	struct entry *next;
	void *key;
	size_t size;
};

static ABT_mutex_memory mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory notempty_cond_mem = ABT_COND_INITIALIZER;
static ABT_cond_memory wait_cond_mem = ABT_COND_INITIALIZER;
static ABT_cond_memory sync_cond_mem = ABT_COND_INITIALIZER;

static struct fs_flush_list {
	struct entry *head;
	struct entry **tail;
} flush_list = {
	NULL, &flush_list.head
};

static int
get_num_threads(void)
{
	int num;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	ABT_mutex_lock(mutex);
	num = num_threads;
	ABT_mutex_unlock(mutex);
	return (num);
}

static void
set_num_threads(int num)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	ABT_mutex_lock(mutex);
	num_threads = num;
	ABT_mutex_unlock(mutex);
}

static void
flush_thread_term(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond wait_cond = ABT_COND_MEMORY_GET_HANDLE(&wait_cond_mem);

	ABT_mutex_lock(mutex);
	++num_stopped_threads;
	if (num_stopped_threads == num_threads)
		ABT_cond_signal(wait_cond);
	ABT_mutex_unlock(mutex);
}

int
fs_inode_flush_enq(void *key, size_t size)
{
	struct entry *e;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond notempty_cond =
		ABT_COND_MEMORY_GET_HANDLE(&notempty_cond_mem);
	static const char diag[] = "fs_inode_flush_enq";

	if (get_num_threads() <= 0)
		return (0);

	log_debug("%s: %s (%ld)", diag, (char *)key, size);
	e = malloc(sizeof *e);
	if (e == NULL) {
		log_error("%s: %s (%ld): no memory", diag, (char *)key, size);
		return (1);
	}
	e->next = NULL;
	e->key = malloc(size);
	if (e->key == NULL) {
		log_error("%s: %s (%ld): no memory", diag, (char *)key, size);
		free(e);
		return (1);
	}
	memcpy(e->key, key, size);
	e->size = size;

	ABT_mutex_lock(mutex);
	*flush_list.tail = e;
	flush_list.tail = &e->next;
	ABT_cond_signal(notempty_cond);
	ABT_mutex_unlock(mutex);

	return (0);
}

static int num_deq_wait = 0;

static struct entry *
fs_inode_flush_deq(void)
{
	struct entry *e = NULL;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond notempty_cond =
		ABT_COND_MEMORY_GET_HANDLE(&notempty_cond_mem);
	ABT_cond sync_cond = ABT_COND_MEMORY_GET_HANDLE(&sync_cond_mem);

	ABT_mutex_lock(mutex);
	while (flush_list.head == NULL && !stop_requested) {
		++num_deq_wait;
		if (num_deq_wait == num_threads)
			ABT_cond_broadcast(sync_cond);
		ABT_cond_wait(notempty_cond, mutex);
		--num_deq_wait;
	}
	if (flush_list.head) {
		e = flush_list.head;
		flush_list.head = e->next;
	}
	if (flush_list.head == NULL)
		flush_list.tail = &flush_list.head;
	ABT_mutex_unlock(mutex);

	return (e);
}

void
fs_inode_flush_sync(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond sync_cond = ABT_COND_MEMORY_GET_HANDLE(&sync_cond_mem);

	if (get_num_threads() <= 0)
		return;

	fs_server_rpc_wait_disable();
	ABT_mutex_lock(mutex);
	while (num_deq_wait < num_threads && !stop_requested)
		ABT_cond_wait(sync_cond, mutex);
	ABT_mutex_unlock(mutex);
	fs_server_rpc_wait_enable();
}

void
fs_inode_flush_wait(void)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);
	ABT_cond notempty_cond =
		ABT_COND_MEMORY_GET_HANDLE(&notempty_cond_mem);
	ABT_cond sync_cond = ABT_COND_MEMORY_GET_HANDLE(&sync_cond_mem);
	ABT_cond wait_cond = ABT_COND_MEMORY_GET_HANDLE(&wait_cond_mem);

	if (get_num_threads() <= 0)
		return;

	fs_server_rpc_wait_disable();
	ABT_mutex_lock(mutex);
	stop_requested = 1;
	ABT_cond_broadcast(notempty_cond);
	ABT_cond_broadcast(sync_cond);
	ABT_mutex_unlock(mutex);

	ABT_mutex_lock(mutex);
	while (num_stopped_threads < num_threads)
		ABT_cond_wait(wait_cond, mutex);
	ABT_mutex_unlock(mutex);
}

static struct entry *
fs_inode_flush_traverse(int (*func)(void *, size_t, void *), void *u)
{
	struct entry **prev, *n, *next;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&mutex_mem);

	ABT_mutex_lock(mutex);
	prev = &flush_list.head;
	for (n = flush_list.head; n != NULL; n = next) {
		next = n->next;
		switch (func(n->key, n->size, u)) {
		case 0:
			/* continues */
			prev = &n->next;
			break;
		case 1:
			/* delete the entry */
			*prev = next;
			if (next == NULL)
				flush_list.tail = prev;
			ABT_mutex_unlock(mutex);
			return (n);
		case -1:
		default:
			/* traversal stops */
			ABT_mutex_unlock(mutex);
			return (NULL);
		}
	}
	ABT_mutex_unlock(mutex);
	return (NULL);
}

static int
print_entry(void *e, size_t s, void *u)
{
	char *c = e;

	printf("%s\n", c);
	return (0);
}

static void *
flush_thread(void *a)
{
	struct entry *e;

	while (1) {
		e = fs_inode_flush_deq();
		if (e == NULL)
			break;
		if (fs_server_get_rpc_last_interval() >= 0)
			fs_server_rpc_wait();
		fs_inode_flush(e->key, e->size);
		free(e->key);
		free(e);
	}
	flush_thread_term();
	return (NULL);
}

void
fs_inode_flush_thread_start(int nthreads)
{
	pthread_t th;

	set_num_threads(nthreads);
	for (; nthreads > 0; --nthreads) {
		pthread_create(&th, NULL, flush_thread, NULL);
		pthread_detach(th);
	}
}

void
fs_inode_flush_list_display()
{
	fs_inode_flush_traverse(print_entry, NULL);
}
