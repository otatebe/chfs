#include <stdlib.h>
#include <margo.h>
#include <mercury_proc_string.h>
#include "kv_err.h"
#include "kv_types.h"
#include "fs_types.h"
#include "backend.h"
#include "fs.h"
#include "key.h"
#include "log.h"

static void
backend_cache_local(char *path, size_t psize, char *buf, size_t *sizep,
	mode_t mode, size_t chunk_size)
{
	int err;
	static const char diag[] = "backend_cache_local";

	err = fs_inode_write(path, psize, buf, sizep, 0,
			mode | CHFS_O_CACHE, chunk_size);
	if (err != KV_SUCCESS) {
		if (err == KV_ERR_NO_SPACE)
			log_notice("%s: %s: %s", diag, path,
					kv_err_string(err));
		else
			log_error("%s: %s: %s", diag, path, kv_err_string(err));
	}
}

char *
backend_read_cache_local(char *path, size_t psize, size_t chunk_size,
	struct fs_stat *stp, size_t *size)
{
	size_t s;
	struct fs_stat st;
	char *buf = backend_read(path, psize, chunk_size, &st, &s);
	int index = key_index(path, psize);

	if (buf != NULL) {
		backend_cache_local(path, psize, buf, &s, st.mode, chunk_size);
		if (size)
			*size = s;
		if (stp)
			*stp = st;
		log_debug("cache: path=%s index=%d size=%ld", path, index, s);
	}
	return (buf);
}
