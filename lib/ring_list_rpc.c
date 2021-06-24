#include <margo.h>
#include "ring_types.h"
#include "ring_list.h"
#include "ring_list_rpc.h"
#include "log.h"

static int ring_list_rpc_timeout_msec;

static struct env {
	margo_instance_id mid;
	hg_id_t node_list_rpc;
} env;

DECLARE_MARGO_RPC_HANDLER(node_list)

static hg_return_t
create_rpc_handle(const char *server, hg_id_t rpc_id, hg_handle_t *h,
	const char *diag)
{
	hg_addr_t addr;
	hg_return_t ret;

	ret = margo_addr_lookup(env.mid, server, &addr);
	if (ret != HG_SUCCESS) {
		log_error("%s (lookup): %s", diag, HG_Error_to_string(ret));
		return (ret);
	}
	ret = margo_create(env.mid, addr, rpc_id, h);
	if (ret != HG_SUCCESS)
		log_error("%s (create): %s", diag, HG_Error_to_string(ret));
	margo_addr_free(env.mid, addr);
	return (ret);
}

hg_return_t
ring_list_rpc_node_list(const char *server)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	int32_t in = 0;
	node_list_t out;
	static const char diag[] = "ring_list_rpc_node_list";

	ret = create_rpc_handle(server, env.node_list_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, &in, ring_list_rpc_timeout_msec);
	if (ret != HG_SUCCESS) {
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));
		goto err;
	}
	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_output): %s", diag, HG_Error_to_string(ret));
		goto err;
	}
	ring_list_update(&out);
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

void
ring_list_rpc_init(margo_instance_id mid, int timeout)
{
	env.mid = mid;
	ring_list_rpc_timeout_msec = timeout;
	env.node_list_rpc = MARGO_REGISTER(mid, "node_list", int32_t,
		node_list_t, node_list);
}

static void
node_list(hg_handle_t h)
{
	hg_return_t ret;
	int32_t in;
	node_list_t out;
	static const char diag[] = "node_list RPC";

	log_debug("%s", diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ring_list_copy(&out);
	ret = margo_respond(h, &out);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	ring_list_copy_free(&out);
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(node_list)
