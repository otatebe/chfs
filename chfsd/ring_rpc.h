hg_return_t
ring_rpc_join(const char *server, char **prev);

hg_return_t
ring_rpc_set_next(const char *server, char *host);

hg_return_t
ring_rpc_set_prev(const char *server, char *host);

void ring_rpc_init(margo_instance_id mid, int timeout);

void ring_set_heartbeat_timeout(int timeout);
void ring_heartbeat();
int ring_heartbeat_is_timeout();
void ring_start_election();
void ring_wait_coordinator_rpc();
