#define NDEBUG

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <abt.h>
#include "ll.h"
#include "hash.h"

#define ENTRY_LOCKED 1

typedef struct hash_entry {
	void *data;	/* data storage */
	void *key;	/* key */
	size_t key_size;	/* key size */
	unsigned int hash_signature;	/* speeds up lookups for strings */
	short status;	/* holds locked bit */
	short num_waiters;	/* number of threads waiting */
	llh_t waiters;	/* threads waiting for entry */
	struct hash_entry *next_entry;	/* ptr to next entry in bucket */
	struct hash_entry *right_entry;	/* next entry in master chain */
	struct hash_entry *left_entry;	/* previous entry in master */
} hash_entry_t;

typedef struct hash_waiter {
	ll_t list;	/* list pointer */
	int wakeup;	/* flag for cv */
	hash_entry_t *entry;	/* which entry we're waiting for */
	ABT_cond cv;	/* condition variable we block on */
} hash_waiter_t;

struct hash {
	ABT_mutex lock;	/* mutext to protect hash table */
	int size;	/* number of buckets */
	int operator_wait_count;	/* #threads waiting to op */
	int get_wait_count;	/* #threads waiting to use get */
	int lock_status;	/* -1 op, 0 unused + get count */
	ABT_cond operate_cv;	/* waiters for operate */
	ABT_cond get_cv;	/* waiters for get during op */
	hash_entry_t **table;	/* buckets */
	hash_entry_t *start;	/* first entry in master chain */
};

/* call while lock is held */
static int
hash_check(hash_t *ptr)
{
	int i, count1, count2;
	hash_entry_t *tmp;

	count1 = 0;
	for (i = 0; i < ptr->size; ++i) {
		tmp = ptr->table[i];
		while (tmp) {
			int waiters = ll_check(&tmp->waiters);
			assert(waiters == tmp->num_waiters);
			++count1;
			tmp = tmp->next_entry;
		}
	}
	tmp = ptr->start;
	count2 = 0;
	if (tmp) {
		++count2;
		assert(tmp->right_entry == NULL);
		tmp = tmp->left_entry;
	}
	while (tmp) {
		if (tmp->left_entry != NULL)
			assert(tmp->left_entry->right_entry == tmp);
		++count2;
		tmp = tmp->left_entry;
	}
	assert(count2 == count1);
	return (1);
}

static unsigned
hash_string(char *s, size_t size)
{
	unsigned result = 0;

	while (size-- > 0)
		result += (result << 3) + *s++;
	return (result);
}

hash_t *
hash_make(int size)
{
	hash_t *ptr;

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return (NULL);
	ptr->size = size;
	ptr->table = malloc(sizeof(hash_entry_t *) * size);
	if (ptr->table == NULL) {
		free(ptr);
		return (NULL);
	}
	ptr->operator_wait_count = 0;
	ptr->get_wait_count = 0;
	ptr->lock_status = 0;
	ptr->start = NULL;
	memset(ptr->table, 0, sizeof(hash_entry_t *) * size);
	ABT_mutex_create(&ptr->lock);
	ABT_cond_create(&ptr->operate_cv);
	ABT_cond_create(&ptr->get_cv);
	assert(ABT_mutex_lock(ptr->lock) == 0 &&
	       hash_check(ptr) &&
	       ABT_mutex_unlock(ptr->lock) == 0);
	return (ptr);
}

static void **
hash_find_unlocked(hash_t *tbl, char *key, size_t key_size, unsigned int sig,
	unsigned int bucket)
{
	hash_entry_t *tmp;

	assert(hash_check(tbl));
	while (tbl->operator_wait_count || tbl->lock_status < 0) {
		++tbl->get_wait_count;
		ABT_cond_wait(tbl->get_cv, tbl->lock);
		--tbl->get_wait_count;
	}
	tmp = tbl->table[bucket];
	while (tmp != NULL) {
		if (tmp->hash_signature == sig && tmp->key_size == key_size &&
			memcmp(tmp->key, key, key_size) == 0)
			break;
		tmp = tmp->next_entry;
	}
	if (tmp) {
		if (tmp->num_waiters || (tmp->status & ENTRY_LOCKED)) {
			hash_waiter_t wait;
			hash_waiter_t *tst;

			wait.wakeup = 0;
			wait.entry = tmp;
			ABT_cond_create(&wait.cv);
			++tmp->num_waiters;
			ll_enqueue(&tmp->waiters, &wait.list);

			while (wait.wakeup == 0)
				ABT_cond_wait(wait.cv, tbl->lock);
			tst = (hash_waiter_t *)ll_dequeue(&tmp->waiters);
			assert(tst == &wait);
			--tmp->num_waiters;
			ABT_cond_free(&wait.cv);
		}
		++tbl->lock_status;
		tmp->status |= ENTRY_LOCKED;
		assert(hash_check(tbl));
		return (&tmp->data);
	}
	assert(hash_check(tbl));
	return (NULL);
}

void **
hash_get(hash_t *tbl, char *key, size_t key_size)
{
	unsigned int sig;
	unsigned int bucket;
	hash_entry_t *new;
	void **data;

	bucket = (sig = hash_string(key, key_size)) % tbl->size;
	ABT_mutex_lock(tbl->lock);
	data = hash_find_unlocked(tbl, key, key_size, sig, bucket);
	if (data) {
		ABT_mutex_unlock(tbl->lock);
		return (data);
	}

	/* not found. insert new entry into bucket */
	new = malloc(sizeof(*new));
	if (new == NULL)
		return (NULL);
	new->key = malloc(key_size);
	if (new->key == NULL) {
		free(new);
		return (NULL);
	}
	memcpy(new->key, key, key_size);
	new->key_size = key_size;
	new->hash_signature = sig;
	/* hook into chain from tbl */
	new->right_entry = NULL;
	if ((new->left_entry = tbl->start) != NULL) {
		assert(tbl->start->right_entry == NULL);
		tbl->start->right_entry = new;
	}
	tbl->start = new;
	/* hook into bucket chain */
	new->next_entry = tbl->table[bucket];
	tbl->table[bucket] = new;
	new->data = NULL;	/* so we know that it is new */
	new->status = ENTRY_LOCKED;
	new->num_waiters = 0;
	ll_init(&new->waiters);
	++tbl->lock_status;
	assert(hash_check(tbl));
	ABT_mutex_unlock(tbl->lock);
	return (&new->data);
}

void **
hash_find(hash_t *tbl, char *key, size_t key_size)
{
	unsigned int sig;
	unsigned int bucket;
	void **data;

	bucket = (sig = hash_string(key, key_size)) % tbl->size;
	ABT_mutex_lock(tbl->lock);
	data = hash_find_unlocked(tbl, key, key_size, sig, bucket);
	ABT_mutex_unlock(tbl->lock);
	return (data);
}

int
hash_release(hash_t *tbl, void **data)
{
	hash_entry_t *tmp = (hash_entry_t *)data;
	hash_waiter_t *sleeper = NULL;
	int op_wait;

	ABT_mutex_lock(tbl->lock);
	assert(hash_check(tbl));
	assert(tbl->lock_status > 0);
	assert(tmp->status & ENTRY_LOCKED);
	tmp->status &= ~ENTRY_LOCKED;
	--tbl->lock_status;
	op_wait = (tbl->operator_wait_count && tbl->lock_status == 0);
	if (tmp->num_waiters) {
		sleeper = (hash_waiter_t *)ll_peek(&tmp->waiters);
		sleeper->wakeup = 1;
	}
	assert(hash_check(tbl));
	ABT_mutex_unlock(tbl->lock);
	if (op_wait)
		ABT_cond_broadcast(tbl->operate_cv);
	if (sleeper)
		ABT_cond_signal(sleeper->cv);
	return (0);
}

void *
hash_delete(hash_t *tbl, void **dataptr)
{
	hash_waiter_t *sleeper = NULL;
	hash_entry_t *act, *tmp, **prev;
	unsigned int sig;
	char *old;
	int bucket, op_wait;

	act = (hash_entry_t *)dataptr;
	ABT_mutex_lock(tbl->lock);
	assert(hash_check(tbl));
	assert(act->status & ENTRY_LOCKED);
	sig = hash_string(act->key, act->key_size);
	tmp = tbl->table[(bucket = sig % tbl->size)];
	prev = tbl->table + bucket;
	for (; tmp != NULL; tmp = tmp->next_entry) {
		if (tmp == act)
			break;
		prev = &tmp->next_entry;
	}
	assert(tmp != NULL);
	old = tmp->data;
	--tbl->lock_status;
	op_wait = (tbl->operator_wait_count && tbl->lock_status == 0);
	if (tmp->num_waiters) {	/* others are waiting so keep entry here */
		if (tmp->num_waiters) {
			sleeper = (hash_waiter_t *)ll_peek(&tmp->waiters);
			sleeper->wakeup = 1;
			tmp->data = NULL;
			tmp->status &= ~ENTRY_LOCKED;
			tmp = NULL;	/* so we don't free it later */
		}
	}
	else {
		hash_entry_t *r, *l;
		/*
		 * tmp now points to entry marked for deletion, prev
		 * to address of storage of next pointer pointing to
		 * tmp.  remove from bucket chain first.
		 */
		assert(hash_check(tbl));
		free(tmp->key);
		*prev = tmp->next_entry;
		/* now remove from dbly linked tbl chain */
		r = tmp->right_entry;
		l = tmp->left_entry;
		if (r != NULL)
			r->left_entry = l;
		else
			tbl->start = l;
		if (l != NULL)
			l->right_entry = r;
		assert(hash_check(tbl));
	}
	assert(hash_check(tbl));
	ABT_mutex_unlock(tbl->lock);
	if (tmp)
		free(tmp);
	if (op_wait)
		ABT_cond_broadcast(tbl->operate_cv);
	if (sleeper)
		ABT_cond_signal(sleeper->cv);
	return (old);
}

int
hash_operate(hash_t *tbl, void (*ptr)(void *, size_t, void **, void *),
	void *usr_arg)
{
	hash_entry_t *tmp;
	int c = 0;

	ABT_mutex_lock(tbl->lock);
	while (tbl->lock_status) {
		++tbl->operator_wait_count;
		ABT_cond_wait(tbl->operate_cv, tbl->lock);
		--tbl->operator_wait_count;
	}
	tmp = tbl->start;
	while (tmp) {
		(*ptr)(tmp->key, tmp->key_size, &tmp->data, usr_arg);
		tmp = tmp->left_entry;
		++c;
	}
	if (tbl->get_wait_count)
		ABT_cond_broadcast(tbl->get_cv);
	ABT_mutex_unlock(tbl->lock);
	return (c);
}
