MERCURY_GEN_PROC(fs_time_t,
	((int64_t)(sec))((int64_t)(nsec)))

typedef struct fs_stat {
	uint32_t mode;
	uint32_t uid, gid;
	uint64_t size;
	uint64_t chunk_size;
	fs_time_t mtime, ctime;
} fs_stat_t;

MERCURY_GEN_STRUCT_PROC(fs_stat_t,
	((uint32_t)(mode))\
	((uint32_t)(uid))((uint32_t)(gid))\
	((uint64_t)(size))((uint64_t)(chunk_size))\
	((fs_time_t)(mtime))((fs_time_t)(ctime)))

MERCURY_GEN_PROC(fs_create_in_t,
	((kv_byte_t)(key))\
	((uint32_t)(mode))\
	((uint32_t)(uid))((uint32_t)(gid))\
	((uint64_t)(chunk_size)))

typedef struct {
	fs_stat_t st;
	int32_t err;
} fs_stat_out_t;

static inline hg_return_t
hg_proc_fs_stat_out_t(hg_proc_t proc, void *data)
{
	fs_stat_out_t *k = data;
	hg_return_t ret;

	ret = hg_proc_int32_t(proc, &k->err);
	if (ret != HG_SUCCESS || k->err != 0)
		return (ret);
	return (hg_proc_fs_stat_t(proc, &k->st));
}

MERCURY_GEN_PROC(fs_write_in_t,
	((kv_byte_t)(key))\
	((kv_byte_t)(value))\
	((hg_size_t)(offset))\
	((hg_size_t)(chunk_size))\
	((uint32_t)(mode)))

MERCURY_GEN_PROC(fs_read_in_t, ((kv_byte_t)(key))\
	((hg_size_t)(size))((hg_size_t)(offset)))

MERCURY_GEN_PROC(fs_file_info_t, ((hg_string_t)(name))((fs_stat_t)(sb)))

typedef struct {
	int32_t err, n;
	fs_file_info_t *fi;
} fs_readdir_out_t;

static inline hg_return_t
hg_proc_fs_readdir_out_t(hg_proc_t proc, void *data)
{
	fs_readdir_out_t *k = data;
	hg_return_t ret;
	int i;

	ret = hg_proc_int32_t(proc, &k->err);
	if (ret != HG_SUCCESS || k->err != 0)
		return (ret);
	ret = hg_proc_int32_t(proc, &k->n);
	if (ret != HG_SUCCESS)
		return (ret);
	if (hg_proc_get_op(proc) == HG_DECODE)
		k->fi = malloc(sizeof(fs_file_info_t) * k->n);
	assert(k->fi);
	for (i = 0; i < k->n; ++i)
		ret = hg_proc_fs_file_info_t(proc, &k->fi[i]);
	if (ret != HG_SUCCESS)
		return (ret);
	if (hg_proc_get_op(proc) == HG_FREE)
		free(k->fi);
	return (ret);
}
