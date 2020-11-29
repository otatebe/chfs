#include "kv_err.h"

#define X(a) #a,
static char *kv_error_list[] = { KV_ERROR };
#undef X

char *
kv_err_string(int err)
{
	if (err < 0 || err > KV_ERR_UNKNOWN)
		err = KV_ERR_UNKNOWN;
	return (kv_error_list[err]);
}
