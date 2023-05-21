#include <errno.h>
#include <margo.h>
#include "kv_err.h"
#include "log.h"

void
chfs_set_errno(hg_return_t ret, int err)
{
	if (ret != HG_SUCCESS) {
		log_notice("chfs_err: %s", HG_Error_to_string(ret));
		errno = ENOTCONN;
		return;
	}
	switch (err) {
	case KV_SUCCESS:
		break;
	case KV_ERR_EXIST:
		errno = EEXIST;
		break;
	case  KV_ERR_NO_ENTRY:
		errno = ENOENT;
		break;
	case KV_ERR_SERVER_DOWN:
	case KV_ERR_LOOKUP:
	case KV_ERR_BULK_CREATE:
	case KV_ERR_BULK_TRANSFER:
		log_notice("chfs_err: %s", kv_err_string(err));
		errno = ENOTCONN;
		break;
	case KV_ERR_NO_MEMORY:
		errno = ENOMEM;
		break;
	case KV_ERR_NOT_SUPPORTED:
		errno = ENOTSUP;
		break;
	case KV_ERR_TOO_LONG:
	case KV_ERR_OUT_OF_RANGE:
		errno = E2BIG;
		break;
	case KV_ERR_METADATA_SIZE_MISMATCH:
		errno = EUCLEAN;
		break;
	case KV_ERR_NO_SPACE:
		errno = ENOSPC;
		break;
	case KV_ERR_UNKNOWN:
	default:
		log_notice("chfs_err: %s", kv_err_string(err));
		errno = EPERM;
		break;
	}
}
