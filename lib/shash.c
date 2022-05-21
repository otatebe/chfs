#include <stdlib.h>
#include <string.h>
#include "shash.h"

struct shash_entry {
	void *data;			/* data storage */
	void *key;			/* key */
	size_t key_size;		/* key size */
	unsigned int hash_signature;	/* speeds up lookups for strings */
	struct shash_entry *next_entry;	/* ptr to next entry in bucket */
	struct shash_entry *right_entry; /* next entry in master chain */
	struct shash_entry *left_entry;  /* previous entry in master */
};

struct shash {
	int size;			/* number of buckets */
	struct shash_entry **table;	/* buckets */
	struct shash_entry *start;	/* first entry in master chain */
};

static unsigned
shash_string(const char *s, size_t size)
{
	unsigned result = 0;

	while (size-- > 0)
		result += (result << 3) + *s++;
	return (result);
}

struct shash *
shash_make(int size)
{
	struct shash *ptr;

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return (NULL);
	ptr->size = size;
	ptr->table = malloc(sizeof(struct shash_entry *) * size);
	if (ptr->table == NULL) {
		free(ptr);
		return (NULL);
	}
	ptr->start = NULL;
	memset(ptr->table, 0, sizeof(struct shash_entry *) * size);
	return (ptr);
}

static void**
shash_find_internal(struct shash *tbl, const char *key, size_t key_size,
	unsigned int sig, unsigned int bucket)
{
	struct shash_entry *tmp;

	tmp = tbl->table[bucket];
	while (tmp != NULL) {
		if (tmp->hash_signature == sig && tmp->key_size == key_size &&
			memcmp(tmp->key, key, key_size) == 0)
			break;
		tmp = tmp->next_entry;
	}
	if (tmp)
		return (&tmp->data);

	return (NULL);
}

void**
shash_get(struct shash *tbl, const char *key, size_t key_size)
{
	unsigned int sig;
	unsigned int bucket;
	struct shash_entry *new;
	void **data;

	bucket = (sig = shash_string(key, key_size)) % tbl->size;
	data = shash_find_internal(tbl, key, key_size, sig, bucket);
	if (data)
		return (data);

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
	if ((new->left_entry = tbl->start) != NULL)
		tbl->start->right_entry = new;
	tbl->start = new;
	/* hook into bucket chain */
	new->next_entry = tbl->table[bucket];
	tbl->table[bucket] = new;
	new->data = NULL;	/* so we know that it is new */
	return (&new->data);
}

void**
shash_find(struct shash *tbl, const char *key, size_t key_size)
{
	unsigned int sig;
	unsigned int bucket;

	bucket = (sig = shash_string(key, key_size)) % tbl->size;
	return (shash_find_internal(tbl, key, key_size, sig, bucket));
}

void *
shash_delete(struct shash *tbl, void **dataptr)
{
	struct shash_entry *act, *tmp, **prev;
	unsigned int sig;
	char *old;
	int bucket;

	act = (struct shash_entry *)dataptr;
	sig = shash_string(act->key, act->key_size);
	tmp = tbl->table[(bucket = sig % tbl->size)];
	prev = tbl->table + bucket;
	for (; tmp != NULL; tmp = tmp->next_entry) {
		if (tmp == act)
			break;
		prev = &tmp->next_entry;
	}
	old = tmp->data;
	/*
	 * tmp now points to entry marked for deletion, prev
	 * to address of storage of next pointer pointing to
	 * tmp.  remove from bucket chain first.
	 */
	free(tmp->key);
	*prev = tmp->next_entry;
	free(tmp);
	return (old);
}

int
shash_operate(struct shash *tbl, void (*ptr)(void *, size_t, void **, void *),
	void *usr_arg)
{
	struct shash_entry *tmp;
	int c = 0;

	tmp = tbl->start;
	while (tmp) {
		(*ptr)(tmp->key, tmp->key_size, &tmp->data, usr_arg);
		tmp = tmp->left_entry;
		++c;
	}
	return (c);
}

void
shash_free(struct shash *tbl)
{
	int i;
	struct shash_entry *tmp, *next;

	if (tbl == NULL)
		return;
	for (i = 0; i < tbl->size; ++i) {
		for (tmp = tbl->table[i]; tmp != NULL; tmp = next) {
			next = tmp->next_entry;
			free(tmp->key);
			free(tmp);
		}
	}
	free(tbl->table);
	free(tbl);
}
