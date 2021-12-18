typedef struct timespec fs_timespec_t;

MERCURY_GEN_STRUCT_PROC(fs_timespec_t,
	((int64_t)(tv_sec))((int64_t)(tv_nsec)))

typedef struct fs_stat {
	uint32_t mode;
	uint32_t uid, gid;
	uint64_t size;
	uint64_t chunk_size;
	struct timespec mtime, ctime;
} fs_stat_t;

MERCURY_GEN_STRUCT_PROC(fs_stat_t,
	((uint32_t)(mode))\
	((uint32_t)(uid))((uint32_t)(gid))\
	((uint64_t)(size))((uint64_t)(chunk_size))\
	((fs_timespec_t)(mtime))((fs_timespec_t)(ctime)))

MERCURY_GEN_PROC(fs_create_in_t,
	((kv_byte_t)(key))\
	((kv_byte_t)(value))\
	((uint32_t)(mode))\
	((uint32_t)(uid))((uint32_t)(gid))\
	((uint64_t)(chunk_size)))

MERCURY_GEN_PROC(fs_stat_out_t,
	 ((int32_t)(err))((fs_stat_t)(st)))

MERCURY_GEN_PROC(fs_write_in_t,
	((kv_byte_t)(key))\
	((kv_byte_t)(value))\
	((hg_size_t)(offset))\
	((hg_size_t)(chunk_size))\
	((uint32_t)(mode)))

MERCURY_GEN_PROC(fs_write_rdma_in_t,
	((kv_byte_t)(key))\
	((hg_string_t)(client))\
	((hg_size_t)(offset))\
	((hg_size_t)(value_size))\
	((hg_bulk_t)(value))\
	((hg_size_t)(chunk_size))\
	((uint32_t)(mode)))

MERCURY_GEN_PROC(fs_read_in_t, ((kv_byte_t)(key))\
	((hg_size_t)(size))((hg_size_t)(offset)))

MERCURY_GEN_PROC(fs_copy_rdma_in_t,
	((kv_byte_t)(key))\
	((hg_string_t)(client))\
	((fs_stat_t)(stat))\
	((hg_bulk_t)(value))\
	((hg_size_t)(value_size))\
	((int32_t)(flag)))

MERCURY_GEN_PROC(fs_truncate_in_t,
	((kv_byte_t)(key))\
	((hg_size_t)(len)))

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
	if (ret != HG_SUCCESS)
		return (ret);
	ret = hg_proc_int32_t(proc, &k->n);
	if (ret != HG_SUCCESS)
		return (ret);
	if (hg_proc_get_op(proc) == HG_DECODE)
		k->fi = malloc(sizeof(fs_file_info_t) * k->n);
	for (i = 0; i < k->n; ++i) {
		ret = hg_proc_fs_file_info_t(proc, &k->fi[i]);
		if (ret != HG_SUCCESS)
			return (ret);
	}
	if (hg_proc_get_op(proc) == HG_FREE)
		free(k->fi);
	return (ret);
}

#define CHFS_FS_DIRTY		0x1

#define FLAGS_SHIFT		16
#define MODE_MASK(m)		((m) & ((1 << FLAGS_SHIFT) - 1))
#define MODE_FLAGS(m, f)	((m) | (f) << FLAGS_SHIFT)
#define FLAGS_FROM_MODE(m)	((m) >> FLAGS_SHIFT)
