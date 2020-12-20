typedef struct {
	size_t s;
	void *v;
} kv_byte_t;

static inline hg_return_t
hg_proc_kv_byte_t(hg_proc_t proc, void *data)
{
	kv_byte_t *k = data;
	hg_return_t ret;

	ret = hg_proc_hg_size_t(proc, &k->s);
	if (ret != HG_SUCCESS)
		return (ret);
	if (hg_proc_get_op(proc) == HG_DECODE)
		k->v = malloc(k->s);
	ret = hg_proc_memcpy(proc, k->v, k->s);
	if (ret != HG_SUCCESS)
		return (ret);
	if (hg_proc_get_op(proc) == HG_FREE)
		free(k->v);
	return (ret);
}

MERCURY_GEN_PROC(kv_put_in_t,
	((kv_byte_t)(key))\
	((kv_byte_t)(value))\
	((hg_size_t)(offset)))

MERCURY_GEN_PROC(kv_put_rdma_in_t,
	((kv_byte_t)(key))\
	((hg_string_t)(client))\
	((hg_size_t)(offset))\
	((hg_size_t)(value_size))\
	((hg_bulk_t)(value)))

MERCURY_GEN_PROC(kv_get_in_t,
	((kv_byte_t)(key))\
	((hg_size_t)(value_size))\
	((hg_size_t)(offset)))

MERCURY_GEN_PROC(kv_get_out_t,
	((int32_t)(err))((kv_byte_t)(value)))

MERCURY_GEN_PROC(kv_get_rdma_out_t,
	((int32_t)(err))((hg_size_t)(value_size)))
