#include <string.h>
#include <errno.h>
#include "kv_err.h"
#include "log.h"

int
fs_err(int err, const char *diag)
{
        if (err >= 0)
                return (KV_SUCCESS);

        switch (-err) {
        case EEXIST:
                return (KV_ERR_EXIST);
        case ENOENT:
                return (KV_ERR_NO_ENTRY);
        case ENOMEM:
                return (KV_ERR_NO_MEMORY);
        case ENOTSUP:
                return (KV_ERR_NOT_SUPPORTED);
        case ENOSPC:
                return (KV_ERR_NO_SPACE);
        default:
                log_notice("fs_err (%s): %s", diag, strerror(-err));
                return (KV_ERR_UNKNOWN);
        }
}
