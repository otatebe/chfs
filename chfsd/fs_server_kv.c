#include <margo.h>
#include "ring.h"
#include "ring_types.h"
#include "ring_rpc.h"
#include "ring_list.h"
#include "kv_types.h"
#include "kv_err.h"
#include "kv.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "fs.h"
#include "log.h"

static void inode_read_rdma(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_read_rdma)

static void inode_readdir(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_readdir)

void
fs_server_init_more(margo_instance_id mid, char *db_dir, size_t db_size)
{
	hg_id_t read_rdma_rpc, readdir_rpc;

	read_rdma_rpc = MARGO_REGISTER(mid, "inode_read_rdma", kv_put_rdma_in_t,
		kv_get_rdma_out_t, inode_read_rdma);
	readdir_rpc = MARGO_REGISTER(mid, "inode_readdir", hg_string_t,
		fs_readdir_out_t, inode_readdir);

	fs_client_init_more_internal(read_rdma_rpc, readdir_rpc);
	kv_init(db_dir, "cmap", "kv.db", db_size);
}

void
fs_server_term_more()
{
	kv_term();
}

struct read_rdma_cb_arg {
	margo_instance_id mid;
	hg_addr_t addr;
	hg_bulk_t bulk;
	size_t value_size, offset;
};

void
read_rdma_cb(const char *value, size_t value_size, void *arg)
{
	struct read_rdma_cb_arg *a = arg;
	void *v = (void *)value;
	hg_bulk_t bulk;
	hg_return_t ret;
	static const char diag[] = "read_rdma_cb";

	if (a->offset >= value_size)
		value_size = 0;
	else
		value_size -= a->offset;
	if (value_size > a->value_size)
		value_size = a->value_size;
	if (value_size == 0)
		goto finish;
	v += a->offset;
	ret = margo_bulk_create(a->mid, 1, &v, &value_size, HG_BULK_READ_ONLY,
		&bulk);
	if (ret != HG_SUCCESS) {
		log_error("%s (bulk_create): %s", diag,
			HG_Error_to_string(ret));
		goto finish;
	}
	ret = margo_bulk_transfer(a->mid, HG_BULK_PUSH, a->addr, a->bulk, 0,
		bulk, 0, value_size);
	if (ret != HG_SUCCESS)
		log_error("%s (bulk_transfer): %s", diag,
			HG_Error_to_string(ret));
	ret = margo_bulk_free(bulk);
	if (ret != HG_SUCCESS)
		log_error("%s (bulk_free): %s", diag, HG_Error_to_string(ret));
finish:
	a->value_size = value_size;
}

static void
inode_read_rdma(hg_handle_t h)
{
	hg_return_t ret;
	kv_put_rdma_in_t in;
	kv_get_rdma_out_t out;
	char *self, *target;
	margo_instance_id mid = margo_hg_handle_get_instance(h);
	hg_addr_t client_addr;
	struct read_rdma_cb_arg a;
	static const char diag[] = "inode_read_rdma RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.key.v);

	memset(&out, 0, sizeof(out));
	ret = margo_addr_lookup(mid, in.client, &client_addr);
	if (ret != HG_SUCCESS) {
		out.err = KV_ERR_LOOKUP;
		goto err_free_input;
	}
	out.value_size = in.value_size;

	self = ring_get_self();
	target = ring_list_lookup(in.key.v, in.key.s);
	if (strcmp(self, target) != 0) {
		ret = fs_rpc_inode_read_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			&out.err);
		if (ret != HG_SUCCESS)
			out.err = KV_ERR_SERVER_DOWN;
	} else {
		a.mid = mid;
		a.addr = client_addr;
		a.offset = in.offset + fs_inode_msize();
		a.bulk = in.value;
		a.value_size = in.value_size;
		out.err = kv_get_cb(in.key.v, in.key.s, read_rdma_cb, &a);
		if (out.err == KV_SUCCESS)
			out.value_size = a.value_size;
	}
	free(target);
	ring_release_self();
	margo_addr_free(mid, client_addr);
err_free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(inode_read_rdma)

struct fs_readdir_arg {
	char path[PATH_MAX];
	int n, size, pathlen;
	fs_file_info_t *fi;
};

static void
free_fs_readdir_arg(struct fs_readdir_arg *a)
{
	int i;

	for (i = 0; i < a->n; ++i)
		free(a->fi[i].name);
	free(a->fi);
}

static void
fs_add_entry(const char *name, struct fs_stat *st, struct fs_readdir_arg *a)
{
	fs_file_info_t *tfi;
	const char *s = name;

	while (*s && *s != '/')
		++s;
	if (*s == '/')
		return;

	if (a->n >= a->size) {
		tfi = realloc(a->fi, sizeof(a->fi[0]) * a->size * 2);
		if (tfi == NULL) {
			log_error("fs_add_entry: no memory");
			return;
		}
		a->fi = tfi;
		a->size *= 2;
	}
	a->fi[a->n].name = strdup(name);
	if (a->fi[a->n].name == NULL) {
		log_error("fs_add_entry: no memory");
		return;
	}
	a->fi[a->n].sb = *st;
	++a->n;
}

int
fs_readdir_cb(const char *key, size_t key_size, const char *value,
	size_t value_size, void *arg)
{
	struct fs_readdir_arg *a = arg;
	int ksize = strlen(key);
	struct fs_stat *st = (struct fs_stat *)value;

	if (ksize + 1 == key_size && a->pathlen < ksize
		&& strncmp(a->path, key, a->pathlen) == 0)
		fs_add_entry(key + a->pathlen, st, a);
	return (0);
}

static void
inode_readdir(hg_handle_t h)
{
	hg_string_t path;
	struct fs_readdir_arg a;
	fs_readdir_out_t out;
	hg_return_t ret;
	static const char diag[] = "inode_readdir RPC";

	ret = margo_get_input(h, &path);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: path=%s", diag, path);

	a.n = 0;
	a.size = 1000;
	a.fi = malloc(sizeof(a.fi[0]) * a.size);
	if (a.fi == NULL) {
		log_error("%s: no memory", diag);
		return;
	}
	a.pathlen = strlen(path);
	if (a.pathlen > PATH_MAX - 2) {
		log_error("%s: too long name: %s (%d)", diag, path, a.pathlen);
		free(a.fi);
		return;
	}
	strcpy(a.path, path);
	if (a.pathlen > 0 && path[a.pathlen - 1] != '/') {
		strcat(a.path, "/");
		a.pathlen += 1;
	}
	ret = margo_free_input(h, &path);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	memset(&out, 0, sizeof(out));
	out.err = kv_get_all_cb(fs_readdir_cb, &a);
	if (out.err == KV_SUCCESS) {
		out.n = a.n;
		out.fi = a.fi;
	}

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	free_fs_readdir_arg(&a);

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(inode_readdir)
