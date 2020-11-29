#define KV_ERROR \
	X(KV_SUCCESS)		\
	X(KV_ERR_EXIST)		\
	X(KV_ERR_NO_ENTRY)	\
	X(KV_ERR_SERVER_DOWN)	\
	X(KV_ERR_LOOKUP)	\
	X(KV_ERR_NO_MEMORY)	\
	X(KV_ERR_NOT_SUPPORTED)	\
	X(KV_ERR_UNKNOWN)

#define X(a) a,
enum { KV_ERROR };
#undef X

char *kv_err_string(int);
