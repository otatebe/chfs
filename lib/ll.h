/* linked list */

typedef struct ll ll_t;

struct ll
{
	ll_t *n;	/* next data */
};

/* linked list header */
typedef struct llh
{
	ll_t *front;	/* pointer to the first entry */
	ll_t **back;	/* address of storage of the last entry */
} llh_t;

/*
 * +--------+------+
 * |  front | back +
 * +--------+------+
 *     |         \___
 *     V             \|
 *   +---+   +---+   +---+
 *   | n +---+>n |---+>n |
 *   +---+   +---+   +---+
 */

void ll_init(llh_t *head);
void ll_enqueue(llh_t *head, ll_t *data);
ll_t *ll_peek(llh_t *head);
ll_t *ll_dequeue(llh_t *head);
ll_t *ll_traverse(llh_t *head, int (*func)(void *, void *), void *user);
/* make sure the list isn't corrupt and returns number of list items */
int ll_check(llh_t *head);
