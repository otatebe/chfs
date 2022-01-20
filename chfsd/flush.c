#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "fs.h"
#include "log.h"

struct entry {
	struct entry *next;
	void *key;
	size_t size;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static struct fs_flush_list {
	struct entry *head;
	struct entry **tail;
} flush_list = {
	NULL, &flush_list.head
};

int
fs_inode_flush_enq(void *key, size_t size)
{
	struct entry *e;

	log_debug("fs_inode_flush_enq: %s (%ld)", (char *)key, size);
	e = malloc(sizeof *e);
	if (e == NULL)
		return (1);
	e->next = NULL;
	e->key = malloc(size);
	if (e->key == NULL) {
		free(e);
		return (1);
	}
	memcpy(e->key, key, size);
	e->size = size;

	pthread_mutex_lock(&mutex);
	*flush_list.tail = e;
	flush_list.tail = &e->next;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);

	return (0);
}

static struct entry *
fs_inode_flush_deq(void)
{
	struct entry *e;

	pthread_mutex_lock(&mutex);
	while (flush_list.head == NULL)
		pthread_cond_wait(&cond, &mutex);
	e = flush_list.head;
	flush_list.head = e->next;
	if (flush_list.head == NULL)
		flush_list.tail = &flush_list.head;
	pthread_mutex_unlock(&mutex);

	return (e);
}

static struct entry *
fs_inode_flush_traverse(int (*func)(void *, size_t, void *), void *u)
{
	struct entry **prev, *n, *next;

	pthread_mutex_lock(&mutex);
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
			pthread_mutex_unlock(&mutex);
			return (n);
		case -1:
		default:
			/* traversal stops */
			pthread_mutex_unlock(&mutex);
			return (NULL);
		}
	}
	pthread_mutex_unlock(&mutex);
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
		fs_inode_flush(e->key, e->size);
		free(e->key);
		free(e);
	}
	return (NULL);
}

void
fs_inode_flush_thread_start()
{
	pthread_t th;

	pthread_create(&th, NULL, flush_thread, NULL);
	pthread_detach(th);
}

void
fs_inode_flush_list_display()
{
	fs_inode_flush_traverse(print_entry, NULL);
}
