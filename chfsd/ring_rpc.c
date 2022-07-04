#include <stdlib.h>
#include <unistd.h>
#include <margo.h>
#include "ring.h"
#include "ring_types.h"
#include "ring_rpc.h"
#include "ring_list.h"
#include "log.h"

static int ring_rpc_timeout_msec;
static char *self, *self_name;

static struct env {
	margo_instance_id mid;
	hg_id_t join_rpc, set_next_rpc, set_prev_rpc;
	hg_id_t list_rpc;
	hg_id_t election_rpc, coordinator_rpc;
} env;

DECLARE_MARGO_RPC_HANDLER(join)
DECLARE_MARGO_RPC_HANDLER(set_next)
DECLARE_MARGO_RPC_HANDLER(set_prev)
DECLARE_MARGO_RPC_HANDLER(list)
DECLARE_MARGO_RPC_HANDLER(election)
DECLARE_MARGO_RPC_HANDLER(coordinator)

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
ring_rpc_join(const char *server, char **prev)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	char *out, *save_out = NULL;
	static const char diag[] = "ring_rpc_join";

	ret = create_rpc_handle(server, env.join_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, &self, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS) {
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));
		goto err;
	}
	ret = margo_get_output(h, &out);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_output): %s", diag, HG_Error_to_string(ret));
		goto err;
	}
	if (out == NULL) {
		log_error("%s: out is NULL", diag);
		save_out = out;
	} else
		save_out = strdup(out);
	ret = margo_free_output(h, &out);
err:
	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	if (ret == HG_SUCCESS)
		*prev = save_out;
	return (ret);
}

hg_return_t
ring_rpc_set_next(const char *server, char *host)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	static const char diag[] = "ring_rpc_set_next";

	ret = create_rpc_handle(server, env.set_next_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, &host, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS)
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));

	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

hg_return_t
ring_rpc_set_prev(const char *server, char *host)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	static const char diag[] = "ring_rpc_set_prev";

	ret = create_rpc_handle(server, env.set_prev_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, &host, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS)
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));

	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

static hg_return_t
ring_rpc_list(const char *server, node_list_t *list)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	node_list_t new_list = { 0, NULL };
	static const char diag[] = "ring_rpc_list";

	ret = create_rpc_handle(server, env.list_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	if (list == NULL) {
		new_list.n = 1;
		new_list.s = malloc(sizeof(*new_list.s));
		if (new_list.s == NULL) {
			log_error("%s: no memory", diag);
			return (HG_NOMEM);
		}
		new_list.s[0].address = self;
		new_list.s[0].name = self_name;
		list = &new_list;
	} else {
		/* space already allocated in hg_proc_string_list_t() */
		list->s[list->n].address = self;
		list->s[list->n].name = self_name;
		++list->n;
	}
	ret = margo_forward_timed(h, list, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS)
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));
	/* decrement required not to free 'self' above in margo_free_input */
	--list->n;

	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	free(new_list.s);
	return (ret);
}

static hg_return_t
ring_rpc_election(const char *server, node_list_t *list)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	node_list_t new_list = { 0, NULL };
	static const char diag[] = "ring_rpc_election";

	ret = create_rpc_handle(server, env.election_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	if (list == NULL) {
		new_list.n = 1;
		new_list.s = malloc(sizeof(*new_list.s));
		if (new_list.s == NULL) {
			log_error("%s: no memory", diag);
			return (HG_NOMEM);
		}
		new_list.s[0].address = self;
		new_list.s[0].name = self_name;
		list = &new_list;
	} else {
		list->s[list->n].address = self;
		list->s[list->n].name = self_name;
		++list->n;
	}
	ret = margo_forward_timed(h, list, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS)
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));
	--list->n;

	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	free(new_list.s);
	return (ret);
}

static hg_return_t
ring_rpc_coordinator(const char *server, coordinator_t *list)
{
	hg_handle_t h;
	hg_return_t ret, ret2;
	static const char diag[] = "ring_rpc_coordinator";

	ret = create_rpc_handle(server, env.coordinator_rpc, &h, diag);
	if (ret != HG_SUCCESS)
		return (ret);

	ret = margo_forward_timed(h, list, ring_rpc_timeout_msec);
	if (ret != HG_SUCCESS)
		log_error("%s (forward): %s", diag, HG_Error_to_string(ret));

	ret2 = margo_destroy(h);
	if (ret == HG_SUCCESS)
		ret = ret2;
	return (ret);
}

static ABT_mutex join_mutex;

void
ring_rpc_init(margo_instance_id mid, int timeout)
{
	env.mid = mid;
	ring_rpc_timeout_msec = timeout;
	env.join_rpc = MARGO_REGISTER(mid, "join", hg_string_t, hg_string_t,
		join);
	env.set_next_rpc = MARGO_REGISTER(mid, "set_next", hg_string_t, void,
		set_next);
	margo_registered_disable_response(mid, env.set_next_rpc, HG_TRUE);
	env.set_prev_rpc = MARGO_REGISTER(mid, "set_prev", hg_string_t, void,
		set_prev);
	margo_registered_disable_response(mid, env.set_prev_rpc, HG_TRUE);
	env.list_rpc = MARGO_REGISTER(mid, "list", node_list_t, void, list);
	margo_registered_disable_response(mid, env.list_rpc, HG_TRUE);
	env.election_rpc = MARGO_REGISTER(mid, "election", node_list_t, void,
		election);
	margo_registered_disable_response(mid, env.election_rpc, HG_TRUE);
	env.coordinator_rpc = MARGO_REGISTER(mid, "coordinator",
		coordinator_t, void, coordinator);
	margo_registered_disable_response(mid, env.coordinator_rpc, HG_TRUE);

	ABT_mutex_create(&join_mutex);
	self = ring_get_self();
	self_name = ring_get_self_name();
}

static void
join(hg_handle_t h)
{
	hg_return_t ret;
	char *in, *prev;
	int prev_prev = 0;
	static const char diag[] = "join RPC";

	log_debug("%s", diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	ABT_mutex_lock(join_mutex);
	prev = ring_get_prev();
	/* election starts */
	ret = ring_rpc_set_next(prev, in);
	if (ret != HG_SUCCESS) {
		log_notice("%s (rpc_set_next): %s", diag,
			HG_Error_to_string(ret));
		ring_release_prev();
		prev = ring_get_prev_prev();
		/* election starts */
		ret = ring_rpc_set_next(prev, in);
		if (ret != HG_SUCCESS)
			log_error("%s (rpc_set_next): %s", diag,
				HG_Error_to_string(ret));
		prev_prev = 1;
	}
	ring_set_prev(in);
	ABT_mutex_unlock(join_mutex);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_respond(h, &prev);
	if (ret != HG_SUCCESS)
		log_error("%s (respond): %s", diag, HG_Error_to_string(ret));
	if (prev_prev == 0)
		ring_release_prev();
	else
		ring_release_prev_prev();
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(join)

/* this assumes ring_get_next() is called */
static int
ring_fix_next(char *next, int election)
{
	char *next_next;
	static const char diag[] = "ring_fix_next";
	hg_return_t ret;
	int r = 0;

	log_debug("%s: remove %s (%d)", diag, next, election);
	next_next = ring_get_next_next();
	if (next_next == NULL || strcmp(next, next_next) == 0) {
		log_error("%s: no more server", diag);
		r = -1;
		goto release_next_next;
	}
	ring_set_next(next_next);

	ret = ring_rpc_set_prev(next_next, self);
	if (ret != HG_SUCCESS) {
		log_error("%s (set_prev): %s", diag, HG_Error_to_string(ret));
		r = -1;
		goto release_next_next;
	}
	if (election) {
		/* election starts */
		ret = ring_rpc_election(next_next, NULL);
		if (ret != HG_SUCCESS) {
			log_error("%s (election): %s", diag,
				HG_Error_to_string(ret));
			r = -1;
		}
	}
release_next_next:
	ring_release_next_next();
	return (r);
}

static time_t heartbeat_time;
static int heartbeat_timeout = 10;

void
ring_set_heartbeat_timeout(int timeout)
{
	heartbeat_timeout = timeout;
}

void
ring_heartbeat()
{
	char *next;
	hg_return_t ret;

	log_debug("heartbeat");
	while (1) {
		next = ring_get_next();
		ret = ring_rpc_list(next, NULL);
		if (ret == HG_SUCCESS)
			break;
		log_notice("heartbeat: %s", HG_Error_to_string(ret));
		if (ring_fix_next(next, 1) == -1)
			break;
		ring_release_next();
	}
	ring_release_next();
}

int
ring_heartbeat_is_timeout()
{
	return (time(NULL) - heartbeat_time > heartbeat_timeout);
}

void
ring_start_election()
{
	char *next;
	hg_return_t ret;

	log_debug("election starts");
	heartbeat_time = time(NULL);
	while (1) {
		next = ring_get_next();
		ret = ring_rpc_election(next, NULL);
		if (ret == HG_SUCCESS)
			break;
		log_notice("start_election: %s", HG_Error_to_string(ret));
		if (ring_fix_next(next, 0) == -1)
			break;
		ring_release_next();
	}
	ring_release_next();
}

static void
set_next(hg_handle_t h)
{
	hg_return_t ret;
	char *in;
	static const char diag[] = "set_next RPC";

	log_debug("%s", diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		margo_destroy(h);
		return;
	}
	ring_set_next(in);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	ring_start_election();
}
DEFINE_MARGO_RPC_HANDLER(set_next)

static void
set_prev(hg_handle_t h)
{
	hg_return_t ret;
	char *in;
	static const char diag[] = "set_prev RPC";

	log_debug("%s", diag);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	ring_set_prev(in);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(set_prev)

static void
list(hg_handle_t h)
{
	hg_return_t ret;
	node_list_t in;
	char *next;
	int i;
	static const char diag[] = "list RPC";

	log_debug("%s", diag);
	heartbeat_time = time(NULL);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	for (i = 0; i < in.n; ++i)
		log_debug("[%d] %s %s", i, in.s[i].address, in.s[i].name);
	for (i = 0; i < in.n; ++i)
		if (strcmp(in.s[i].address, self) == 0)
			break;
	if (i == in.n) {
		while (1) {
			next = ring_get_next();
			ret = ring_rpc_list(next, &in);
			if (ret == HG_SUCCESS)
				break;
			log_notice("list: %s", HG_Error_to_string(ret));
			if (ring_fix_next(next, 1) == -1)
				break;
			ring_release_next();
		}
		ring_release_next();
	}

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(list)

static void
remove_host(coordinator_t *c, char *host)
{
	int i;

	log_debug("remove_host: %s", host);
	for (i = 0; i < c->list.n; ++i)
		if (strcmp(c->list.s[i].address, host) == 0)
			break;
	if (i < c->list.n) {
		c->list.n = c->list.n - 1;
		free(c->list.s[i].address);
		free(c->list.s[i].name);
		for (; i < c->list.n; ++i)
			c->list.s[i] = c->list.s[i + 1];
		--c->ttl;
	}
}

static void
election(hg_handle_t h)
{
	hg_return_t ret;
	node_list_t in;
	coordinator_t in3;
	char *next;
	int i;
	static const char diag[] = "election RPC";

	log_debug("%s", diag);
	heartbeat_time = time(NULL);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		goto destroy;
	}
	for (i = 0; i < in.n; ++i)
		if (strcmp(in.s[i].address, self) == 0)
			break;
	if (i == in.n) {
		while (1) {
			next = ring_get_next();
			ret = ring_rpc_election(next, &in);
			if (ret == HG_SUCCESS)
				break;
			log_notice("election: %s", HG_Error_to_string(ret));
			if (ring_fix_next(next, 0) == -1)
				break;
			ring_release_next();
		}
		ring_release_next();
	} else {
		in3.ttl = in.n - 1;
		in3.list = in;
		while (1) {
			next = ring_get_next();
			ret = ring_rpc_coordinator(next, &in3);
			if (ret == HG_SUCCESS)
				break;
			log_notice("election (coordinator): %s",
				HG_Error_to_string(ret));
			remove_host(&in3, next);
			if (ring_fix_next(next, 0) == -1)
				break;
			ring_release_next();
		}
		ring_release_next();
	}

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));
destroy:
	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));
}
DEFINE_MARGO_RPC_HANDLER(election)

static int coordinator_rpc_done = 0;
static ABT_mutex_memory coord_mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory coord_cond_mem = ABT_COND_INITIALIZER;

void
ring_wait_coordinator_rpc()
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&coord_mutex_mem);
	ABT_cond cond = ABT_COND_MEMORY_GET_HANDLE(&coord_cond_mem);

	ABT_mutex_lock(mutex);
	while (!coordinator_rpc_done)
		ABT_cond_wait(cond, mutex);
	ABT_mutex_unlock(mutex);
}

static void
coordinator(hg_handle_t h)
{
	hg_return_t ret;
	coordinator_t in;
	char *next;
	int i;
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&coord_mutex_mem);
	ABT_cond cond = ABT_COND_MEMORY_GET_HANDLE(&coord_cond_mem);
	static const char diag[] = "coordinator RPC";

	log_debug("%s", diag);
	heartbeat_time = time(NULL);
	ret = margo_get_input(h, &in);
	if (ret != HG_SUCCESS) {
		log_error("%s (get_input): %s", diag, HG_Error_to_string(ret));
		margo_destroy(h);
		return;
	}
	for (i = 0; i < in.list.n; ++i)
		log_debug("[%d] %s %s", i, in.list.s[i].address,
			in.list.s[i].name);
	if (in.ttl > 0) {
		--in.ttl;
		while (1) {
			next = ring_get_next();
			ret = ring_rpc_coordinator(next, &in);
			if (ret == HG_SUCCESS)
				break;
			log_notice("%s: %s", diag, HG_Error_to_string(ret));
			remove_host(&in, next);
			if (ring_fix_next(next, 0) == -1)
				break;
			ring_release_next();
		}
		ring_release_next();
	}
	ring_list_update(&in.list);

	for (i = 0; i < in.list.n; ++i)
		if (strcmp(self, in.list.s[i].address) == 0)
			break;

	i = (i + 2) % in.list.n;
	ring_set_next_next(in.list.s[i].address);
	i = i - 4;
	while (i < 0)
		i += in.list.n;
	ring_set_prev_prev(in.list.s[i].address);

	ret = margo_free_input(h, &in);
	if (ret != HG_SUCCESS)
		log_error("%s (free_input): %s", diag, HG_Error_to_string(ret));

	ret = margo_destroy(h);
	if (ret != HG_SUCCESS)
		log_error("%s (destroy): %s", diag, HG_Error_to_string(ret));

	ABT_mutex_lock(mutex);
	coordinator_rpc_done = 1;
	ABT_mutex_unlock(mutex);
	ABT_cond_signal(cond);
}
DEFINE_MARGO_RPC_HANDLER(coordinator)
