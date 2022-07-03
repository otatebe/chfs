void fs_server_rpc_begin(void *func, const char *diag);
void fs_server_rpc_end(void *func, const char *diag);
void fs_server_rpc_wait(void);
void fs_server_set_rpc_last_interval(int second);
int fs_server_get_rpc_last_interval(void);
