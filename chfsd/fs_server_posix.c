#include <dirent.h>
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
	fs_inode_init(db_dir);
}

void
fs_server_term_more()
{}

static void
inode_read_rdma(hg_handle_t h)
{
	hg_return_t ret;
	kv_put_rdma_in_t in;
	kv_get_rdma_out_t out;
	char *self, *target;
	margo_instance_id mid = margo_hg_handle_get_instance(h);
	hg_addr_t client_addr;
	hg_bulk_t bulk;
	void *buf;
	static const char diag[] = "inode_read_rdma RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.key.v);

	memset(&out, 0, sizeof(out));
	out.value_size = in.value_size;
	if (out.value_size == 0) {
		out.err = KV_SUCCESS;
		goto free_input;
	}
	ret = margo_addr_lookup(mid, in.client, &client_addr);
	if (ret != HG_SUCCESS) {
		log_error("%s (lookup): %s", diag, HG_Error_to_string(ret));
		out.err = KV_ERR_LOOKUP;
		goto free_input;
	}

	self = ring_get_self();
	target = ring_list_lookup(in.key.v, in.key.s);
	if (strcmp(self, target) != 0) {
		ret = fs_rpc_inode_read_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			&out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_read_rdma_bulk): %s", diag,
				HG_Error_to_string(ret));
			out.err = KV_ERR_SERVER_DOWN;
		}
	} else {
		buf = malloc(out.value_size);
		if (buf == NULL) {
			log_error("%s: no memory", diag);
			out.err = KV_ERR_NO_MEMORY;
			goto free_target;
		}
		out.err = fs_inode_read(in.key.v, in.key.s, buf,
			&out.value_size, in.offset);
		if (out.err == 0 && out.value_size > 0) {
			ret = margo_bulk_create(mid, 1, &buf, &out.value_size,
				HG_BULK_READ_ONLY, &bulk);
			if (ret != HG_SUCCESS) {
				log_error("%s (bulk_create): %s", diag,
					HG_Error_to_string(ret));
				goto free_buf;
			}
			ret = margo_bulk_transfer(mid, HG_BULK_PUSH,
				client_addr, in.value, 0, bulk, 0,
				out.value_size);
			if (ret != HG_SUCCESS)
				log_error("%s (bulk_transfer): %s", diag,
					HG_Error_to_string(ret));
			ret = margo_bulk_free(bulk);
			if (ret != HG_SUCCESS)
				log_error("%s (bulk_free): %s", diag,
					HG_Error_to_string(ret));
		}
free_buf:
		free(buf);
	}
free_target:
	free(target);
	ring_release_self();
	margo_addr_free(mid, client_addr);
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond) %s", diag, HG_Error_to_string(ret));
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy) %s", diag, HG_Error_to_string(ret));

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
fs_add_entry(struct dirent *dent, void *arg)
{
	struct fs_readdir_arg *a = arg;
	fs_file_info_t *tfi;
	int namelen = strlen(dent->d_name);

	log_debug("add_entry: %s", dent->d_name);
	if (a->pathlen + namelen + 1 > PATH_MAX) {
		log_error("fs_add_entry: too long: %s%s (%d)", a->path,
			dent->d_name, a->pathlen + namelen + 1);
		return;
	}
	strcpy(a->path + a->pathlen, dent->d_name);
	if (!ring_list_is_in_charge(a->path, a->pathlen + namelen + 1))
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
	a->fi[a->n].name = strdup(dent->d_name);
	if (a->fi[a->n].name == NULL) {
		log_error("fs_add_entry: no memory");
		return;
	}
	memset(&a->fi[a->n].sb, 0, sizeof(a->fi[a->n].sb));
	a->fi[a->n].sb.mode = dent->d_type << 12;
	++a->n;
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

	memset(&out, 0, sizeof(out));
	a.n = 0;
	a.size = 1000;
	a.fi = malloc(sizeof(a.fi[0]) * a.size);
	if (a.fi == NULL) {
		log_error("%s: no memory", diag);
		out.err = KV_ERR_NO_MEMORY;
		goto free_input;
	}
	a.pathlen = strlen(path);
	if (a.pathlen > PATH_MAX - 2) {
		log_error("%s: too long path: %s (%d)", diag, path, a.pathlen);
		out.err = KV_ERR_TOO_LONG;
		goto free_input;
	}
	strcpy(a.path, path);
	if (a.pathlen > 0 && a.path[a.pathlen - 1] != '/') {
		a.path[a.pathlen++] = '/';
		a.path[a.pathlen] = '\0';
	}
	out.err = fs_inode_readdir(path, fs_add_entry, &a);
	if (out.err == KV_SUCCESS) {
		out.n = a.n;
		out.fi = a.fi;
	}
free_input:
	ret = margo_free_input(h, &path);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	free_fs_readdir_arg(&a);

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(inode_readdir)
