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

static void inode_create(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_create)

static void inode_stat(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_stat)

static void inode_write(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_write)

static void inode_write(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_write_rdma)

static void inode_read(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_read)

#ifndef USE_ZERO_COPY_READ_RDMA
static void inode_read_rdma(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_read_rdma)
#endif

static void inode_remove(hg_handle_t h);
DECLARE_MARGO_RPC_HANDLER(inode_remove)

void
fs_server_init(margo_instance_id mid, char *db_dir, size_t db_size, int timeout)
{
	hg_id_t create_rpc, stat_rpc, remove_rpc;
	hg_id_t write_rpc, write_rdma_rpc, read_rpc, read_rdma_rpc = -1;

	create_rpc = MARGO_REGISTER(mid, "inode_create", fs_create_in_t,
		int32_t, inode_create);
	stat_rpc = MARGO_REGISTER(mid, "inode_stat", kv_byte_t, fs_stat_out_t,
		inode_stat);
	write_rpc = MARGO_REGISTER(mid, "inode_write", fs_write_in_t,
		kv_get_rdma_out_t, inode_write);
	write_rdma_rpc = MARGO_REGISTER(mid, "inode_write_rdma",
		fs_write_rdma_in_t, kv_get_rdma_out_t, inode_write_rdma);
	read_rpc = MARGO_REGISTER(mid, "inode_read", fs_read_in_t, kv_get_out_t,
		inode_read);
#ifndef USE_ZERO_COPY_READ_RDMA
	read_rdma_rpc = MARGO_REGISTER(mid, "inode_read_rdma", kv_put_rdma_in_t,
		kv_get_rdma_out_t, inode_read_rdma);
#endif
	remove_rpc = MARGO_REGISTER(mid, "inode_remove", kv_byte_t, int32_t,
		inode_remove);

	fs_client_init_internal(mid, timeout, create_rpc, stat_rpc, write_rpc,
		write_rdma_rpc, read_rpc, read_rdma_rpc, remove_rpc);
	fs_server_init_more(mid, db_dir, db_size);

	self = ring_get_self();
}

void
fs_server_term()
{
	fs_server_term_more();
}

static void
inode_create(hg_handle_t h)
{
	hg_return_t ret;
	fs_create_in_t in;
	int32_t err;
	char *target;
	static const char diag[] = "inode_create RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.key.v);

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_create(target, in.key.v, in.key.s, in.uid,
			in.gid, in.mode, in.chunk_size, &err);
		if (ret != HG_SUCCESS)
			err = KV_ERR_SERVER_DOWN;
	} else
		err = fs_inode_create(in.key.v, in.key.s, in.uid, in.gid,
			in.mode, in.chunk_size);
	free(target);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (err == KV_ERR_SERVER_DOWN)
		ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(inode_create)

static void
inode_stat(hg_handle_t h)
{
	hg_return_t ret;
	struct fs_stat sb;
	kv_byte_t in;
	fs_stat_out_t out;
	char *target;
	static const char diag[] = "inode_stat RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.v);

	memset(&out, 0, sizeof(out));
	target = ring_list_lookup(in.v, in.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_stat(target, in.v, in.s, &sb, &out.err);
		if (ret != HG_SUCCESS)
			out.err = KV_ERR_SERVER_DOWN;
	} else
		out.err = fs_inode_stat(in.v, in.s, &sb);
	free(target);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	log_debug("inode_stat: %s", kv_err_string(out.err));
	if (out.err == KV_SUCCESS) {
		out.st.mode = sb.mode;
		out.st.uid = sb.uid;
		out.st.gid = sb.gid;
		out.st.size = sb.size;
		out.st.chunk_size = sb.chunk_size;
		out.st.mtime = sb.ctime;
		out.st.ctime = sb.ctime;
	}
	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(inode_stat)

static void
inode_write(hg_handle_t h)
{
	hg_return_t ret;
	fs_write_in_t in;
	kv_get_rdma_out_t out;
	char *target;
	static const char diag[] = "inode_write RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.key.v);

	out.value_size = in.value.s;
	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_write(target, in.key.v, in.key.s, in.value.v,
			&out.value_size, in.offset, in.mode, in.chunk_size,
			&out.err);
		if (ret != HG_SUCCESS)
			out.err = KV_ERR_SERVER_DOWN;
	} else
		out.err = fs_inode_write(in.key.v, in.key.s, in.value.v,
			&out.value_size, in.offset, in.mode, in.chunk_size);
	free(target);

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
DEFINE_MARGO_RPC_HANDLER(inode_write)

static void
inode_write_rdma(hg_handle_t h)
{
	hg_return_t ret;
	fs_write_rdma_in_t in;
	kv_get_rdma_out_t out;
	char *target;
	margo_instance_id mid = margo_hg_handle_get_instance(h);
	hg_addr_t client_addr;
	hg_bulk_t bulk;
	void *buf;
	static const char diag[] = "inode_write_rdma RPC";

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

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_write_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			in.mode, in.chunk_size, &out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_write_rdma_bulk): %s", diag,
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
		ret = margo_bulk_create(mid, 1, &buf, &out.value_size,
			HG_BULK_WRITE_ONLY, &bulk);
		if (ret != HG_SUCCESS) {
			log_error("%s (bulk_create): %s", diag,
				HG_Error_to_string(ret));
			out.err = KV_ERR_BULK_CREATE;
			goto free_buf;
		}
		ret = margo_bulk_transfer(mid, HG_BULK_PULL, client_addr,
			in.value, 0, bulk, 0, out.value_size);
		if (ret != HG_SUCCESS) {
			log_error("%s (bulk_transfer): %s", diag,
				HG_Error_to_string(ret));
			out.err = KV_ERR_BULK_TRANSFER;
		}
		ret = margo_bulk_free(bulk);
		if (ret != HG_SUCCESS)
			log_error("%s (bulk_free): %s", diag,
				HG_Error_to_string(ret));
		if (out.err == 0)
			out.err = fs_inode_write(in.key.v, in.key.s, buf,
				&out.value_size, in.offset, in.mode,
				in.chunk_size);
free_buf:
		free(buf);
	}
free_target:
	free(target);
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
DEFINE_MARGO_RPC_HANDLER(inode_write_rdma)

static void
inode_read(hg_handle_t h)
{
	hg_return_t ret;
	fs_read_in_t in;
	kv_get_out_t out;
	char *target;
	static const char diag[] = "inode_read RPC";

	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)in.key.v);

	out.value.s = in.size;
	out.value.v = malloc(out.value.s);
	if (out.value.s == 0) {
		out.err = KV_SUCCESS;
		goto free_input;
	}
	if (out.value.v == NULL) {
		log_error("%s: no memory", diag);
		out.value.s = 0;
		out.err = KV_ERR_NO_MEMORY;
		goto free_input;
	}
	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_read(target, in.key.v, in.key.s,
			out.value.v, &out.value.s, in.offset, &out.err);
		if (ret != HG_SUCCESS)
			out.err = KV_ERR_SERVER_DOWN;
	} else
		out.err = fs_inode_read(in.key.v, in.key.s, out.value.v,
			&out.value.s, in.offset);
	free(target);
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	free(out.value.v);
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(inode_read)

#ifndef USE_ZERO_COPY_READ_RDMA
static void
inode_read_rdma(hg_handle_t h)
{
	hg_return_t ret;
	kv_put_rdma_in_t in;
	kv_get_rdma_out_t out;
	char *target;
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

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(self, target) != 0) {
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
				out.err = KV_ERR_BULK_CREATE;
				goto free_buf;
			}
			ret = margo_bulk_transfer(mid, HG_BULK_PUSH,
				client_addr, in.value, 0, bulk, 0,
				out.value_size);
			if (ret != HG_SUCCESS) {
				log_error("%s (bulk_transfer): %s", diag,
					HG_Error_to_string(ret));
				out.err = KV_ERR_BULK_TRANSFER;
			}
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
#endif

static void
inode_remove(hg_handle_t h)
{
	hg_return_t ret;
	kv_byte_t key;
	int32_t err;
	char *target;
	static const char diag[] = "inode_remove RPC";

	ret = margo_get_input(h, &key);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		return;
	}
	log_debug("%s: key=%s", diag, (char *)key.v);

	target = ring_list_lookup(key.v, key.s);
	if (target && strcmp(self, target) != 0) {
		ret = fs_rpc_inode_remove(target, key.v, key.s, &err);
		if (ret != HG_SUCCESS)
			err = KV_ERR_SERVER_DOWN;
	} else
		err = fs_inode_remove(key.v, key.s);
	free(target);

	ret = margo_free_input(h, &key);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (err == KV_ERR_SERVER_DOWN)
		ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(inode_remove)
