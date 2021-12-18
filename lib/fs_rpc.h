struct stat;
struct fs_stat;

hg_return_t
fs_rpc_inode_create(const char *server, void *key, size_t key_size,
	uint32_t uid, uint32_t gid, mode_t mode, size_t chunk_size,
	const void *buf, size_t size, int *errp);

hg_return_t
fs_rpc_inode_stat(const char *server, void *key, size_t key_size,
	struct fs_stat *st, int *errp);

hg_return_t
fs_rpc_inode_write(const char *server, void *key, size_t key_size,
	const void *buf, size_t *size, size_t offset, mode_t mode,
	size_t chunk_size, int *errp);

hg_return_t
fs_rpc_inode_read(const char *server, void *key, size_t key_size, void *buf,
	size_t *size, size_t offset, int *errp);

hg_return_t
fs_rpc_inode_write_rdma_bulk(const char *server, void *key, size_t key_size,
	char *client, hg_bulk_t buf, hg_size_t *size, size_t offset,
	mode_t mode, size_t chunk_size, int *errp);

hg_return_t
fs_rpc_inode_write_rdma(const char *server, void *key, size_t key_size,
	char *client, const void *buf, hg_size_t *size, size_t offset,
	mode_t mode, size_t chunk_size, int *errp);

hg_return_t
fs_rpc_inode_read_rdma_bulk(const char *server, void *key, size_t key_size,
	char *client, hg_bulk_t buf, hg_size_t *size, size_t offset,
	int *errp);

hg_return_t
fs_rpc_inode_read_rdma(const char *server, void *key, size_t key_size,
	char *client, void *buf, hg_size_t *size, size_t offset,
	int *errp);

hg_return_t
fs_rpc_inode_copy_rdma_bulk(const char *server, void *key, size_t key_size,
	char *client, struct fs_stat *st, hg_bulk_t buf, hg_size_t size,
	int *errp);

hg_return_t
fs_rpc_inode_copy_rdma(const char *server, void *key, size_t key_size,
	char *client, struct fs_stat *st, void *buf, hg_size_t size, int *errp);

hg_return_t
fs_rpc_inode_truncate(const char *server, void *key, size_t key_size,
	off_t len, int *errp);

hg_return_t
fs_rpc_inode_remove(const char *server, void *key, size_t key_size, int *errp);

hg_return_t
fs_async_rpc_inode_unlink_chunk_all(const char *server, void *path,
	hg_handle_t *h);

hg_return_t
fs_async_rpc_inode_unlink_chunk_all_wait(hg_handle_t *h, int32_t *errp);

hg_return_t
fs_rpc_readdir(const char *server, const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t),
	int *errp);

void
fs_client_init_internal(margo_instance_id mid, int timeout,
	hg_id_t create_rpc, hg_id_t stat_rpc, hg_id_t write_rpc,
	hg_id_t write_rdma_rpc, hg_id_t read_rpc, hg_id_t read_rdma_rpc,
	hg_id_t copy_rpc, hg_id_t truncate_rpc, hg_id_t remove_rpc);

void
fs_client_init_more_internal(hg_id_t read_rdma_rpc, hg_id_t readdir_rpc,
	hg_id_t unlink_all_rpc);

void fs_client_init(margo_instance_id mid, int timeout);
void fs_client_term(void);
void fs_server_init(margo_instance_id mid, char *db_dir, size_t db_size,
	int timeout, int niothreads);
void fs_server_init_more(margo_instance_id mid, char *db_dir, size_t db_size,
	int niothreads);
void fs_server_term(void);
void fs_server_term_more(void);

void inode_copy_all(void);
