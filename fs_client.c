#include <sys/stat.h>
#include <margo.h>
#include "ring_types.h"
#include "kv_types.h"
#include "fs_types.h"
#include "fs_rpc.h"

#define TIMEOUT_MSEC	(0)

static struct env {
	margo_instance_id mid;
	hg_id_t create_rpc, stat_rpc;
	hg_id_t write_rpc, read_rpc, read_rdma_rpc;
	hg_id_t remove_rpc, readdir_rpc;
} env;

static hg_return_t
create_rpc_handle(const char *server, hg_id_t rpc_id, hg_handle_t *h)
{
	hg_addr_t addr;
	hg_return_t ret;

	ret = margo_addr_lookup(env.mid, server, &addr);
	if (ret != HG_SUCCESS)
		return (ret);
	ret = margo_create(env.mid, addr, rpc_id, h);
	margo_addr_free(env.mid, addr);
	return (ret);
}

hg_return_t
fs_rpc_inode_create(const char *server, void *key, size_t key_size, int32_t uid,
	int32_t gid, mode_t mode, size_t chunk_size, int *errp)
{
	hg_handle_t h;
	fs_create_in_t in;
	hg_return_t ret, ret2;

	ret = create_rpc_handle(server, env.create_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.key.v = key;
	in.key.s = key_size;
	in.st.uid = uid;
	in.st.gid = gid;
	in.st.mode = mode;
	in.st.chunk_size = chunk_size;
	in.st.size = 0;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, errp);
	if (ret != HG_SUCCESS)
		goto err;
	ret = margo_free_output(h, errp);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_stat(const char *server, void *key, size_t key_size,
	struct fs_stat *st, int *errp)
{
	hg_handle_t h;
	kv_byte_t in;
	fs_stat_out_t out;
	hg_return_t ret, ret2;

	ret = create_rpc_handle(server, env.stat_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.v = key;
	in.s = key_size;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = out.err;
	if (out.err == 0) {
		st->mode = out.st.mode;
		st->uid = out.st.uid;
		st->gid = out.st.gid;
		st->size = out.st.size;
		st->chunk_size = out.st.chunk_size;
	}
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_write(const char *server, void *key, size_t key_size,
	const void *buf, size_t *size, size_t offset, mode_t mode,
	size_t chunk_size, int *errp)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	fs_write_in_t in;
	kv_get_rdma_out_t out;

	ret = create_rpc_handle(server, env.write_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.key.v = key;
	in.key.s = key_size;
	in.value.v = (void *)buf;
	in.value.s = *size;
	in.offset = offset;
	in.mode = mode;
	in.chunk_size = chunk_size;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = out.err;
	if (out.err == 0 && *size > out.value_size)
		*size = out.value_size;
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_read(const char *server, void *key, size_t key_size, void *buf,
	size_t *size, size_t offset, int *errp)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	fs_read_in_t in;
	kv_get_out_t out;

	ret = create_rpc_handle(server, env.read_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.key.v = key;
	in.key.s = key_size;
	in.size = *size;
	in.offset = offset;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = out.err;
	if (out.err == 0) {
		if (*size > out.value.s)
			*size = out.value.s;
		memcpy(buf, out.value.v, *size);
	}
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_read_rdma_bulk(const char *server, void *key, size_t key_size,
	char *client, hg_bulk_t buf, hg_size_t *size, size_t offset,
	int *errp)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	kv_put_rdma_in_t in;
	kv_get_rdma_out_t out;

	ret = create_rpc_handle(server, env.read_rdma_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.key.v = key;
	in.key.s = key_size;
	in.client = client;
	in.offset = offset;
	in.value = buf;
	in.value_size = *size;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = out.err;
	if (out.err == 0)
		*size = out.value_size;
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_read_rdma(const char *server, void *key, size_t key_size,
	char *client, void *buf, hg_size_t *size, size_t offset,
	int *errp)
{
	hg_bulk_t bulk;
	hg_return_t ret, ret2;

	ret = margo_bulk_create(env.mid, 1, &buf, size,
		HG_BULK_WRITE_ONLY, &bulk);
	if (ret != HG_SUCCESS)
		return (ret);
	ret = fs_rpc_inode_read_rdma_bulk(server, key, key_size, client,
		bulk, size, offset, errp);

	ret2 = margo_bulk_free(bulk);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_inode_remove(const char *server, void *key, size_t key_size, int *errp)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	kv_byte_t in;
	int32_t err;

	ret = create_rpc_handle(server, env.remove_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	in.v = key;
	in.s = key_size;
	ret = margo_forward_timed(h, &in, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &err);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = err;
	ret = margo_free_output(h, &err);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
fs_rpc_readdir(const char *server, const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t),
	int *errp)
{
	hg_handle_t h;
	fs_readdir_out_t out;
	struct stat sb;
	hg_return_t ret, ret2;
	int i;

	ret = create_rpc_handle(server, env.readdir_rpc, &h);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, &path, TIMEOUT_MSEC);
	if (ret != HG_SUCCESS)
		goto err;

	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS)
		goto err;
	*errp = out.err;
	if (out.err == 0) {
		for (i = 0; i < out.n; ++i) {
			memset(&sb, 0, sizeof(sb));
			sb.st_uid = out.fi[i].sb.uid;
			sb.st_gid = out.fi[i].sb.gid;
			sb.st_mode = out.fi[i].sb.mode;
			if (filler(buf, out.fi[i].name, &sb, 0))
				break;
		}
	}
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

void
fs_client_init_internal(margo_instance_id mid, hg_id_t create_rpc,
	hg_id_t stat_rpc, hg_id_t write_rpc, hg_id_t read_rpc,
	hg_id_t remove_rpc)
{
	env.mid = mid;
	env.create_rpc = create_rpc;
	env.stat_rpc = stat_rpc;
	env.write_rpc = write_rpc;
	env.read_rpc = read_rpc;
	env.remove_rpc = remove_rpc;
}

void
fs_client_init_more_internal(hg_id_t read_rdma_rpc, hg_id_t readdir_rpc)
{
	env.read_rdma_rpc = read_rdma_rpc;
	env.readdir_rpc = readdir_rpc;
}

void
fs_client_init(margo_instance_id mid)
{
	env.mid = mid;
	env.create_rpc = MARGO_REGISTER(mid, "inode_create", fs_create_in_t,
		int32_t, NULL);
	env.stat_rpc = MARGO_REGISTER(mid, "inode_stat", kv_byte_t,
		fs_stat_out_t, NULL);
	env.write_rpc = MARGO_REGISTER(mid, "inode_write", fs_write_in_t,
		kv_get_rdma_out_t, NULL);
	env.read_rpc = MARGO_REGISTER(mid, "inode_read", fs_read_in_t,
		kv_get_out_t, NULL);
	env.read_rdma_rpc = MARGO_REGISTER(mid, "inode_read_rdma",
		kv_put_rdma_in_t, kv_get_rdma_out_t, NULL);
	env.remove_rpc = MARGO_REGISTER(mid, "inode_remove", kv_byte_t,
		int32_t, NULL);
	env.readdir_rpc = MARGO_REGISTER(mid, "inode_readdir",
		hg_string_t, fs_readdir_out_t, NULL);
}
