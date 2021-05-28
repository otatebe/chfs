#include <dirent.h>
#include <margo.h>
#include "config.h"
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

static char *self;

DECLARE_MARGO_RPC_HANDLER(inode_readdir)
DECLARE_MARGO_RPC_HANDLER(inode_unlink_chunk_all)

void
fs_server_init_more(margo_instance_id mid, char *db_dir, size_t db_size,
	int niothreads)
{
	hg_id_t read_rdma_rpc = -1, readdir_rpc, unlink_all_rpc;

#ifdef USE_ZERO_COPY_READ_RDMA
#error posix backend does not support --enable-zero-copy-read-rdma
#endif
	readdir_rpc = MARGO_REGISTER(mid, "inode_readdir", hg_string_t,
		fs_readdir_out_t, inode_readdir);
	unlink_all_rpc = MARGO_REGISTER(mid, "inode_unlink_chunk_all",
		hg_string_t, int32_t, inode_unlink_chunk_all);

	fs_client_init_more_internal(read_rdma_rpc, readdir_rpc,
		unlink_all_rpc);
	fs_inode_init(db_dir, niothreads);

	self = ring_get_self();
}

void
fs_server_term_more()
{}

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

static void
inode_unlink_chunk_all(hg_handle_t h)
{
	hg_string_t path;
	hg_return_t ret;
	int err;
	static const char diag[] = "inode_unlink_chunk_all RPC";

	ret = margo_get_input(h, &path);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: path=%s", diag, path);

	fs_inode_unlink_chunk_all(path);

	ret = margo_free_input(h, &path);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	err = 0;
	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(inode_unlink_chunk_all)
