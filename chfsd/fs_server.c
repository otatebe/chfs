#include <stdlib.h>
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
#include "fs_hook.h"
#include "fs.h"
#include "flush.h"
#include "key.h"
#include "log.h"

static struct {
	margo_instance_id mid;
	char *self;
} env;

DECLARE_MARGO_RPC_HANDLER(inode_create)
DECLARE_MARGO_RPC_HANDLER(inode_stat)
DECLARE_MARGO_RPC_HANDLER(inode_write)
DECLARE_MARGO_RPC_HANDLER(inode_write_rdma)
DECLARE_MARGO_RPC_HANDLER(inode_read)
#ifndef USE_ZERO_COPY_READ_RDMA
DECLARE_MARGO_RPC_HANDLER(inode_read_rdma)
#endif
DECLARE_MARGO_RPC_HANDLER(inode_copy_rdma)
DECLARE_MARGO_RPC_HANDLER(inode_truncate)
DECLARE_MARGO_RPC_HANDLER(inode_remove)
DECLARE_MARGO_RPC_HANDLER(inode_unlink_chunk_all)
DECLARE_MARGO_RPC_HANDLER(inode_sync)

void
fs_server_init(margo_instance_id mid, char *db_dir, size_t db_size, int timeout,
	int niothreads)
{
	hg_id_t create_rpc, stat_rpc, remove_rpc, copy_rdma_rpc;
	hg_id_t write_rpc, write_rdma_rpc, read_rpc, read_rdma_rpc = -1;
	hg_id_t truncate_rpc, unlink_all_rpc, sync_rpc;

	env.mid = mid;
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
	copy_rdma_rpc = MARGO_REGISTER(mid, "inode_copy_rdma",
		fs_copy_rdma_in_t, int32_t, inode_copy_rdma);
	truncate_rpc = MARGO_REGISTER(mid, "inode_truncate", fs_truncate_in_t,
		int32_t, inode_truncate);
	remove_rpc = MARGO_REGISTER(mid, "inode_remove", kv_byte_t, int32_t,
		inode_remove);
	unlink_all_rpc = MARGO_REGISTER(mid, "inode_unlink_chunk_all",
		fs_unlink_all_t, void, inode_unlink_chunk_all);
	margo_registered_disable_response(mid, unlink_all_rpc, HG_TRUE);
	sync_rpc = MARGO_REGISTER(mid, "inode_sync", void, int32_t, inode_sync);

	fs_client_init_internal(mid, timeout, create_rpc, stat_rpc, write_rpc,
		write_rdma_rpc, read_rpc, read_rdma_rpc, copy_rdma_rpc,
		truncate_rpc, remove_rpc, unlink_all_rpc, sync_rpc);
	fs_server_init_more(mid, db_dir, db_size, niothreads);

	env.self = ring_get_self();
}

void
fs_server_term()
{
	fs_server_term_more();
	margo_finalize(env.mid);
}

static void
inode_create(hg_handle_t h)
{
	hg_return_t ret;
	fs_create_in_t in;
	int32_t err = KV_SUCCESS;
	char *target;
	int index;
	static const char diag[] = "inode_create RPC";

	fs_server_rpc_begin((void *)inode_create, diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_create(target, in.key.v, in.key.s, in.uid,
			in.gid, in.mode, in.chunk_size, in.value.v, in.value.s,
			&err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_create) %s:%d: %s", diag,
				(char *)in.key.v, index,
				HG_Error_to_string(ret));
			err = KV_ERR_SERVER_DOWN;
		}
	} else
		err = fs_inode_create(in.key.v, in.key.s, in.uid, in.gid,
			in.mode, in.chunk_size, in.value.v, in.value.s);
	free(target);
	if (err != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(err));

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_create, diag);
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
	int index;
	static const char diag[] = "inode_stat RPC";

	fs_server_rpc_begin((void *)inode_stat, diag);
	memset(&out, 0, sizeof(out));
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.v, in.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.v, index);

	target = ring_list_lookup(in.v, in.s);
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_stat(target, in.v, in.s, &sb, &out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_stat) %s:%d: %s", diag,
				(char *)in.v, index, HG_Error_to_string(ret));
			out.err = KV_ERR_SERVER_DOWN;
		}
	} else
		out.err = fs_inode_stat(in.v, in.s, &sb);
	free(target);
	if (out.err != KV_SUCCESS && out.err != KV_ERR_NO_ENTRY)
		log_error("%s: %s:%d: %s", diag, (char *)in.v, index,
				kv_err_string(out.err));

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	log_debug("inode_stat: %s", kv_err_string(out.err));
	if (out.err == KV_SUCCESS)
		out.st = sb;

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_stat, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_stat)

static void
inode_write(hg_handle_t h)
{
	hg_return_t ret;
	fs_write_in_t in;
	kv_get_rdma_out_t out;
	char *target;
	int index;
	static const char diag[] = "inode_write RPC";

	fs_server_rpc_begin((void *)inode_write, diag);
	memset(&out, 0, sizeof(out));
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

	out.value_size = in.value.s;
	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_write(target, in.key.v, in.key.s, in.value.v,
			&out.value_size, in.offset, in.mode, in.chunk_size,
			&out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_write) %s:%d: %s", diag,
				(char *)in.key.v, index,
				HG_Error_to_string(ret));
			out.err = KV_ERR_SERVER_DOWN;
		}
	} else
		out.err = fs_inode_write(in.key.v, in.key.s, in.value.v,
			&out.value_size, in.offset, in.mode, in.chunk_size);
	free(target);
	if (out.err != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(out.err));

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_write, diag);
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
	int index;
	static const char diag[] = "inode_write_rdma RPC";

	fs_server_rpc_begin((void *)inode_write_rdma, diag);
	memset(&out, 0, sizeof(out));
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

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
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_write_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			in.mode, in.chunk_size, &out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_write_rdma_bulk) %s:%d: %s", diag,
				(char *)in.key.v, index,
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
	if (out.err != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(out.err));
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond) %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy) %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_write_rdma, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_write_rdma)

static void
inode_read(hg_handle_t h)
{
	hg_return_t ret;
	fs_read_in_t in;
	kv_get_out_t out;
	char *target;
	int index;
	static const char diag[] = "inode_read RPC";

	fs_server_rpc_begin((void *)inode_read, diag);
	memset(&out, 0, sizeof(out));
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

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
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_read(target, in.key.v, in.key.s,
			out.value.v, &out.value.s, in.offset, &out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_read) %s:%d: %s", diag,
				(char *)in.key.v, index,
				HG_Error_to_string(ret));
			out.err = KV_ERR_SERVER_DOWN;
		}
	} else
		out.err = fs_inode_read(in.key.v, in.key.s, out.value.v,
			&out.value.s, in.offset);
	free(target);
	if (out.err != KV_SUCCESS && out.err != KV_ERR_NO_ENTRY)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(out.err));
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	free(out.value.v);
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_read, diag);
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
	int index;
	static const char diag[] = "inode_read_rdma RPC";

	fs_server_rpc_begin((void *)inode_read_rdma, diag);
	memset(&out, 0, sizeof(out));
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

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
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_read_rdma_bulk(target, in.key.v, in.key.s,
			in.client, in.value, &out.value_size, in.offset,
			&out.err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_read_rdma_bulk) %s:%d: %s", diag,
				(char *)in.key.v, index,
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
	if (out.err != KV_SUCCESS && out.err != KV_ERR_NO_ENTRY)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(out.err));
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond) %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy) %s", diag, HG_Error_to_string(ret));

	if (out.err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_read_rdma, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_read_rdma)
#endif

static void
inode_copy_rdma(hg_handle_t h)
{
	hg_return_t ret;
	fs_copy_rdma_in_t in;
	int32_t out = KV_SUCCESS;
	char *target;
	margo_instance_id mid = margo_hg_handle_get_instance(h);
	hg_addr_t client_addr;
	hg_bulk_t bulk;
	void *buf;
	int index;
	static const char diag[] = "inode_copy_rdma RPC";

	fs_server_rpc_begin((void *)inode_copy_rdma, diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)in.key.v, index);

	ret = margo_addr_lookup(mid, in.client, &client_addr);
	if (ret != HG_SUCCESS) {
		log_error("%s (lookup): %s", diag, HG_Error_to_string(ret));
		out = KV_ERR_LOOKUP;
		goto free_input;
	}

	if (in.flag == 0) {
		/* may forward RPC */
		target = ring_list_lookup(in.key.v, in.key.s);
		if (target && strcmp(env.self, target) != 0) {
			ret = fs_rpc_inode_copy_rdma_bulk(target,
				in.key.v, in.key.s, in.client, &in.stat,
				in.value, in.value_size, &out);
			if (ret != HG_SUCCESS) {
				log_error("%s (rpc_copy_rdma_bulk) %s:%d: %s",
					diag, (char *)in.key.v, index,
					HG_Error_to_string(ret));
				out = KV_ERR_SERVER_DOWN;
			}
			free(target);
			goto free_addr;
		}
		free(target);
	}

	buf = malloc(in.value_size);
	if (buf == NULL) {
		log_error("%s: no memory", diag);
		out = KV_ERR_NO_MEMORY;
		goto free_addr;
	}
	ret = margo_bulk_create(mid, 1, &buf, &in.value_size,
		HG_BULK_WRITE_ONLY, &bulk);
	if (ret != HG_SUCCESS) {
		log_error("%s (bulk_create): %s", diag,
			HG_Error_to_string(ret));
		out = KV_ERR_BULK_CREATE;
		goto free_buf;
	}
	ret = margo_bulk_transfer(mid, HG_BULK_PULL, client_addr,
		in.value, 0, bulk, 0, in.value_size);
	if (ret != HG_SUCCESS) {
		log_error("%s (bulk_transfer): %s", diag,
			HG_Error_to_string(ret));
		out = KV_ERR_BULK_TRANSFER;
	}
	ret = margo_bulk_free(bulk);
	if (ret != HG_SUCCESS)
		log_error("%s (bulk_free): %s", diag, HG_Error_to_string(ret));
	if (out == KV_SUCCESS)
		out = fs_inode_create_stat(in.key.v, in.key.s, &in.stat,
			buf, in.value_size);
free_buf:
	free(buf);

free_addr:
	margo_addr_free(mid, client_addr);
	if (out != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(out));
free_input:
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond) %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy) %s", diag, HG_Error_to_string(ret));

	if (out == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_copy_rdma, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_copy_rdma)

static void
inode_truncate(hg_handle_t h)
{
	hg_return_t ret;
	fs_truncate_in_t in;
	int32_t err = KV_SUCCESS;
	char *target;
	int index;
	static const char diag[] = "inode_truncate RPC";

	fs_server_rpc_begin((void *)inode_truncate, diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(in.key.v, in.key.s);
	log_debug("%s: key=%s index=%d, len=%ld", diag, (char *)in.key.v,
			index, in.len);

	target = ring_list_lookup(in.key.v, in.key.s);
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_truncate(target, in.key.v, in.key.s, in.len,
			&err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_truncate) %s:%d: %s", diag,
				(char *)in.key.v, index,
				HG_Error_to_string(ret));
			err = KV_ERR_SERVER_DOWN;
		}
	} else
		err = fs_inode_truncate(in.key.v, in.key.s, in.len);
	free(target);
	if (err != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)in.key.v, index,
				kv_err_string(err));

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_truncate, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_truncate)

static void
inode_remove(hg_handle_t h)
{
	hg_return_t ret;
	kv_byte_t key;
	int32_t err = KV_SUCCESS;
	char *target;
	int index;
	static const char diag[] = "inode_remove RPC";

	fs_server_rpc_begin((void *)inode_remove, diag);
	ret = margo_get_input(h, &key);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	index = key_index(key.v, key.s);
	log_debug("%s: key=%s index=%d", diag, (char *)key.v, index);

	target = ring_list_lookup(key.v, key.s);
	if (target && strcmp(env.self, target) != 0) {
		ret = fs_rpc_inode_remove(target, key.v, key.s, &err);
		if (ret != HG_SUCCESS) {
			log_error("%s (rpc_remove) %s:%d: %s", diag,
				(char *)key.v, index,
				HG_Error_to_string(ret));
			err = KV_ERR_SERVER_DOWN;
		}
	} else
		err = fs_inode_remove(key.v, key.s);
	free(target);
	if (err != KV_SUCCESS)
		log_error("%s: %s:%d: %s", diag, (char *)key.v, index,
				kv_err_string(err));

	ret = margo_free_input(h, &key);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	if (err == KV_ERR_SERVER_DOWN)
		ring_start_election();
	fs_server_rpc_end((void *)inode_remove, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_remove)

static void
inode_unlink_chunk_all(hg_handle_t h)
{
	hg_return_t ret;
	fs_unlink_all_t in;
	static const char diag[] = "inode_unlink_chunk_all RPC";

	fs_server_rpc_begin((void *)inode_unlink_chunk_all, diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	log_debug("%s: path=%s index=%d", diag, in.path, in.index);

	fs_inode_unlink_chunk_all(in.path, in.index);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
	fs_server_rpc_end((void *)inode_unlink_chunk_all, diag);
}
DEFINE_MARGO_RPC_HANDLER(inode_unlink_chunk_all)

#ifndef USE_ZERO_COPY_READ_RDMA
void
inode_copy_all(void)
{
}
#endif

static void
inode_sync(hg_handle_t h)
{
	hg_return_t ret;
	int32_t err = KV_SUCCESS;
	static const char diag[] = "inode_sync RPC";

	log_debug("%s", diag);
	fs_inode_flush_sync();

	ret = margo_respond(h, &err);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(inode_sync)
