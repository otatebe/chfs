#include <stdlib.h>
#include <sys/stat.h>
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
#include "shash.h"
#include "log.h"
#include "fs_kv.h"

#ifdef USE_ZERO_COPY_READ_RDMA
DECLARE_MARGO_RPC_HANDLER(inode_read_rdma)
#endif
DECLARE_MARGO_RPC_HANDLER(inode_readdir)

static char *self;

void
fs_server_init_more(margo_instance_id mid, char *db_dir, size_t db_size,
	int niothreads)
{
	hg_id_t read_rdma_rpc = -1, readdir_rpc;

#ifdef USE_ZERO_COPY_READ_RDMA
	read_rdma_rpc = MARGO_REGISTER(mid, "inode_read_rdma", kv_put_rdma_in_t,
		kv_get_rdma_out_t, inode_read_rdma);
#endif
	readdir_rpc = MARGO_REGISTER(mid, "inode_readdir", hg_string_t,
		fs_readdir_out_t, inode_readdir);

	fs_client_init_more_internal(read_rdma_rpc, readdir_rpc);
	kv_init(db_dir, "cmap", "kv.db", db_size);

	self = ring_get_self();
}

void
fs_server_term_more()
{
	kv_term();
}

#ifdef USE_ZERO_COPY_READ_RDMA
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
	struct inode *inode = v;
	hg_bulk_t bulk;
	hg_return_t ret;
	static const char diag[] = "read_rdma_cb";

	if (value_size > fs_msize + inode->size)
		value_size = fs_msize + inode->size;
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
	char *target;
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

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_read_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			&out.err);
		if (ret != HG_SUCCESS)
			out.err = KV_ERR_SERVER_DOWN;
	} else {
		a.mid = mid;
		a.addr = client_addr;
		a.offset = in.offset + fs_msize;
		a.bulk = in.value;
		a.value_size = in.value_size;
		out.err = kv_get_cb(in.key.v, in.key.s, read_rdma_cb, &a);
		if (out.err == KV_SUCCESS)
			out.value_size = a.value_size;
	}
	free(target);
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
#endif

struct fs_readdir_arg {
	char path[PATH_MAX];
	int n, size, pathlen;
	struct shash *hash;
	fs_file_info_t *fi;
};

static void
free_fs_readdir_arg(struct fs_readdir_arg *a)
{
	int i;

	for (i = 0; i < a->n; ++i)
		free(a->fi[i].name);
	free(a->fi);
	shash_free(a->hash);
}

static void
fs_add_ventry(void *name, size_t size, void **d, void *arg)
{
	struct fs_readdir_arg *a = arg;
	int *data = (int *)d;
	fs_file_info_t *tfi;
	static const char diag[] = "fs_add_ventry";

	if (*data == 2)
		return;

	if (a->n >= a->size) {
		tfi = realloc(a->fi, sizeof(a->fi[0]) * a->size * 2);
		if (tfi == NULL) {
			log_error("%s: no memory", diag);
			return;
		}
		a->fi = tfi;
		a->size *= 2;
	}
	a->fi[a->n].name = strndup(name, size);
	if (a->fi[a->n].name == NULL) {
		log_error("%s: no memory", diag);
		return;
	}
	memset(&a->fi[a->n].sb, 0, sizeof(a->fi[a->n].sb));
	a->fi[a->n].sb.mode = S_IFDIR | CHFS_S_IFREP;
	++a->n;
}

static void
fs_add_entry(const char *name, struct inode *ino, struct fs_readdir_arg *a,
	int is_rep)
{
	fs_file_info_t *tfi;
	const char *s = name;
	int *data;
	static const char diag[] = "fs_add_entry";

	while (*s && *s != '/')
		++s;
	if (*s == '/') {
		data = (int *)shash_get(a->hash, name, s - name);
		if (*data == 0)
			*data = 1;
		return;
	} else if (S_ISDIR(ino->mode)) {
		data = (int *)shash_get(a->hash, name, strlen(name));
		*data = 2;
	}

	if (ino->msize != fs_msize)
		return;		/* metadata size mismatch */

	if (a->n >= a->size) {
		tfi = realloc(a->fi, sizeof(a->fi[0]) * a->size * 2);
		if (tfi == NULL) {
			log_error("%s: no memory", diag);
			return;
		}
		a->fi = tfi;
		a->size *= 2;
	}
	a->fi[a->n].name = strdup(name);
	if (a->fi[a->n].name == NULL) {
		log_error("%s: no memory", diag);
		return;
	}
	memset(&a->fi[a->n].sb, 0, sizeof(a->fi[a->n].sb));
	a->fi[a->n].sb.uid = ino->uid;
	a->fi[a->n].sb.gid = ino->gid;
	a->fi[a->n].sb.mode = ino->mode;
	if (is_rep)
		a->fi[a->n].sb.mode |= CHFS_S_IFREP;
	a->fi[a->n].sb.size = ino->size;
	a->fi[a->n].sb.mtime = ino->mtime;
	a->fi[a->n].sb.ctime = ino->ctime;
	++a->n;
}

int
fs_readdir_cb(const char *key, size_t key_size, const char *value,
	size_t value_size, void *arg)
{
	struct fs_readdir_arg *a = arg;
	int ksize = strlen(key);
	struct inode *ino = (struct inode *)value;

	if (ksize + 1 == key_size && a->pathlen < ksize &&
		strncmp(a->path, key, a->pathlen) == 0)
		fs_add_entry(key + a->pathlen, ino, a,
			!ring_list_is_in_charge(key, key_size));
	return (0);
}

#define HASH_SIZE	16381

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
	a.hash = shash_make(HASH_SIZE);
	a.fi = malloc(sizeof(a.fi[0]) * a.size);
	if (a.hash == NULL || a.fi == NULL) {
		log_error("%s: no memory", diag);
		out.err = KV_ERR_NO_MEMORY;
		goto free_input;
	}
	a.pathlen = strlen(path);
	if (a.pathlen > PATH_MAX - 2) {
		log_error("%s: too long name: %s (%d)", diag, path, a.pathlen);
		out.err = KV_ERR_TOO_LONG;
		goto free_input;
	}
	strcpy(a.path, path);
	if (a.pathlen > 0 && a.path[a.pathlen - 1] != '/') {
		a.path[a.pathlen++] = '/';
		a.path[a.pathlen] = '\0';
	}
	out.err = kv_get_all_cb(fs_readdir_cb, &a);
	if (out.err == KV_SUCCESS) {
		shash_operate(a.hash, fs_add_ventry, &a);
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

#ifdef USE_ZERO_COPY_READ_RDMA
static int
copy_all_cb(const char *key, size_t key_size, const char *value,
	size_t value_size, void *arg)
{
	char *target;
	struct fs_stat sb;
	int ret, err;

	memset(&sb, 0, sizeof(sb));
	target = ring_list_lookup(key, key_size);
	ret = fs_rpc_inode_copy_rdma(target, (void *)key, key_size,
		self, &sb, (void *)value, value_size, &err);
	if (ret != HG_SUCCESS) {
		log_error("copy_all_cb (copy_rdma): %s",
				HG_Error_to_string(ret));
		err = KV_ERR_SERVER_DOWN;
	}
	free(target);
	if (err == KV_SUCCESS)
		log_debug("copy_all_cb: %s (%ld)", key, key_size);
	else
		log_error("copy_all_cb: %s (%ld): %s", key, key_size,
				kv_err_string(err));
	return (0);
}

void
inode_copy_all(void)
{
	kv_get_all_cb(copy_all_cb, NULL);
}
#endif
