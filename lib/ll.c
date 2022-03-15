#define NDEBUG

#include <stdlib.h>
#include <assert.h>
#include "ll.h"

void
ll_init(llh_t *head)
{
	head->back = &head->front;
	head->front = NULL;
}

void
ll_enqueue(llh_t *head, ll_t *data)
{
	data->n = NULL;
	*head->back = data;
	head->back = &data->n;
}

ll_t *
ll_peek(llh_t *head)
{
	return (head->front);
}

ll_t *
ll_dequeue(llh_t *head)
{
	ll_t *ptr;

	ptr = head->front;
	if (ptr && ((head->front = ptr->n) == NULL))
		/* last data, change to the initial state */
		head->back = &head->front;
	return (ptr);
}

ll_t *
ll_traverse(llh_t *head, int (*func)(void *, void *), void *user)
{
	ll_t *ptr, **prev;

	prev = &head->front;
	ptr = head->front;
	while (ptr) {
		switch (func(ptr, user)) {
		case 0:
			/* continues */
			prev = &ptr->n;
			ptr = ptr->n;
			break;
		case -1:
			/* the item is deleted */
			if ((*prev = ptr->n) == NULL)
				head->back = prev;
			return (ptr);
		case 1:
		default:
			/* traversal stops */
			return (NULL);
		}
	}
	return (NULL);
}

#ifndef NDEBUG
/* make sure the list isn't corrupt and returns number of list items */
int
ll_check(llh_t *head)
{
	int i = 0;
	ll_t *ptr, **prev;

	prev = &head->front;
	ptr = head->front;
	while (ptr) {
		++i;
		prev = &ptr->n;
		ptr = ptr->n;
	}
	assert(head->back == prev);
	return (i);
}
#endif
