#include <mercury_proc_string.h>

MERCURY_GEN_PROC(node_t, ((hg_string_t)(address))((hg_string_t)(name)))

typedef struct node_list {
	int32_t n;
	node_t *s;
} node_list_t;

static inline hg_return_t
hg_proc_node_list_t(hg_proc_t proc, void *data)
{
	node_list_t *l = data;
	hg_return_t ret;
	int i;

	ret = hg_proc_int32_t(proc, &l->n);
	if (ret != HG_SUCCESS || l->n == 0)
		return (ret);
	if (hg_proc_get_op(proc) == HG_DECODE) {
		/* allocate one more to add self entry in ring_rpc_list() */
		l->s = malloc(sizeof(l->s[0]) * (l->n + 1));
		if (l->s == NULL)
			return (HG_NOMEM);
	}
	for (i = 0; i < l->n; ++i) {
		ret = hg_proc_node_t(proc, &l->s[i]);
		if (ret != HG_SUCCESS)
			return (ret);
	}
	if (hg_proc_get_op(proc) == HG_FREE)
		free(l->s);
	return (ret);
}

MERCURY_GEN_PROC(coordinator_t, ((int32_t)(ttl))((node_list_t)(list)))
