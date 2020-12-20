#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <abt.h>
#include "ring.h"

typedef struct {
	char *host[2];
	int ref_count;
	ABT_mutex mutex;
} ring_node_t;

static ring_node_t self, next, prev;
static ring_node_t next_next, prev_prev;

static void
ring_print_node(ring_node_t *node, const char *diag)
{
	int index = 0;

	if (diag != NULL)
		printf("%s: ", diag);
	ABT_mutex_lock(node->mutex);
	if (node->ref_count > 0 && node->host[1])
		index = 1;
	if (node->host[index])
		printf("%s", node->host[index]);
	printf("\n");
	ABT_mutex_unlock(node->mutex);
}

static void
ring_init_node(const char *host, ring_node_t *node, const char *diag)
{
	if (host == NULL)
		node->host[0] = NULL;
	else
		node->host[0] = strdup(host);
	node->host[1] = NULL;
	node->ref_count = 0;
	ABT_mutex_create(&node->mutex);
	if (diag)
		ring_print_node(node, diag);
}

static void
ring_set_node(const char *host, ring_node_t *node, const char *diag)
{
	int index = 0;

	if (host == NULL)
		return;
	ABT_mutex_lock(node->mutex);
	if (node->ref_count > 0)
		index = 1;
	free(node->host[index]);
	node->host[index] = strdup(host);
	ABT_mutex_unlock(node->mutex);
	if (diag)
		ring_print_node(node, diag);
}

static char *
ring_host(ring_node_t *node)
{
	char *r;

	ABT_mutex_lock(node->mutex);
	++node->ref_count;
	r = node->host[0];
	ABT_mutex_unlock(node->mutex);
	return (r);
}

static void
ring_release_node(ring_node_t *node)
{
	ABT_mutex_lock(node->mutex);
	--node->ref_count;
	if (node->ref_count == 0) {
		if (node->host[1]) {
			free(node->host[0]);
			node->host[0] = node->host[1];
			node->host[1] = NULL;
		}
	}
	ABT_mutex_unlock(node->mutex);
}

void
ring_init(const char *name)
{
	ring_init_node(name, &self, "self");
	ring_init_node(name, &next, "next");
	ring_init_node(name, &next_next, "next_next");
	ring_init_node(name, &prev, "prev");
	ring_init_node(name, &prev_prev, "prev_prev");
}

void
ring_set_next(const char *name)
{
	ring_set_node(name, &next, "next");
}

void
ring_set_next_next(const char *name)
{
	ring_set_node(name, &next_next, "next_next");
}

void
ring_set_prev(const char *name)
{
	ring_set_node(name, &prev, "prev");
}

void
ring_set_prev_prev(const char *name)
{
	ring_set_node(name, &prev_prev, "prev_prev");
}

char *
ring_get_self()
{
	return (ring_host(&self));
}

char *
ring_get_next()
{
	return (ring_host(&next));
}

char *
ring_get_next_next()
{
	return (ring_host(&next_next));
}

char *
ring_get_prev()
{
	return (ring_host(&prev));
}

char *
ring_get_prev_prev()
{
	return (ring_host(&prev_prev));
}

void
ring_release_self()
{
	ring_release_node(&self);
}

void
ring_release_next()
{
	ring_release_node(&next);
}

void
ring_release_next_next()
{
	ring_release_node(&next_next);
}

void
ring_release_prev()
{
	ring_release_node(&prev);
}

void
ring_release_prev_prev()
{
	ring_release_node(&prev_prev);
}
