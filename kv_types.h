#include <assert.h>
#include <mercury_proc_string.h>

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
	assert(k->v);
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

typedef struct {
	kv_byte_t value;
	int32_t err;
} kv_get_out_t;

static inline hg_return_t
hg_proc_kv_get_out_t(hg_proc_t proc, void *data)
{
	kv_get_out_t *k = data;
	hg_return_t ret;

	ret = hg_proc_int32_t(proc, &k->err);
	if (ret != HG_SUCCESS || k->err != 0)
		return (ret);
	return (hg_proc_kv_byte_t(proc, &k->value));
}

typedef struct {
	hg_size_t value_size;
	int32_t err;
} kv_get_rdma_out_t;

static inline hg_return_t
hg_proc_kv_get_rdma_out_t(hg_proc_t proc, void *data)
{
	kv_get_rdma_out_t *k = data;
	hg_return_t ret;

	ret = hg_proc_int32_t(proc, &k->err);
	if (ret != HG_SUCCESS || k->err != 0)
		return (ret);
	return (hg_proc_hg_size_t(proc, &k->value_size));
}

typedef struct {
	int32_t err;
	string_list_t dlist;
} dirlist_t;

static inline hg_return_t
hg_proc_dirlist_t(hg_proc_t proc, void *data)
{
	dirlist_t *k = data;
	hg_return_t ret;

	ret = hg_proc_int32_t(proc, &k->err);
	if (ret != HG_SUCCESS || k->err != 0)
		return (ret);
	return (hg_proc_string_list_t(proc, &k->dlist));
}
