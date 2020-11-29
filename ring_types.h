#include <assert.h>
#include <mercury_proc_string.h>

typedef struct node_list {
	int32_t n;
	hg_string_t *s;
} string_list_t;

static inline hg_return_t
hg_proc_string_list_t(hg_proc_t proc, void *data)
{
	string_list_t *l = data;
	hg_return_t ret;
	int i;

	ret = hg_proc_int32_t(proc, &l->n);
	if (ret != HG_SUCCESS || l->n == 0)
		return (ret);
	if (hg_proc_get_op(proc) == HG_DECODE)
		/* allocate one more to add self entry in ring_rpc_list() */
		l->s = malloc(sizeof(hg_string_t) * (l->n + 1));
	assert(l->s);
	for (i = 0; i < l->n; ++i) {
		ret = hg_proc_hg_string_t(proc, &l->s[i]);
		if (ret != HG_SUCCESS)
			return (ret);
	}
	if (hg_proc_get_op(proc) == HG_FREE)
		free(l->s);
	return (ret);
}

MERCURY_GEN_PROC(coordinator_t, ((int32_t)(ttl))((string_list_t)(list)))
