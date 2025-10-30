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
backend_cache_local(char *path, size_t psize, char *buf, size_t size,
	struct fs_stat *st, size_t chunk_size)
{
	size_t ss = size;
	struct timespec times[2];
	int index = key_index(path, psize), err;
	static const char diag[] = "backend_cache_local";

	err = fs_inode_write(path, psize, buf, &ss, 0,
			st->mode | CHFS_O_CACHE, chunk_size);
	if (err != KV_SUCCESS) {
		if (err == KV_ERR_NO_SPACE)
			log_notice("%s: %s: %s", diag, path,
					kv_err_string(err));
		else
			log_error("%s: %s: %s", diag, path, kv_err_string(err));
		return;
	}
	if (size != ss) {
		err = fs_inode_remove(path, psize);
		if (err == KV_SUCCESS)
			log_info("%s: %s: partial cache removed", diag, path);
		else
			log_error("%s: %s: partial cache cannot be removed: "
				"%s", diag, path, kv_err_string(err));
		return;
	} else {
		times[0] = times[1] = st->mtime;
		fs_inode_utimensat(path, psize, times);
	}
	log_debug("%s: path=%s index=%d size=%ld", diag, path, index, size);
}

char *
backend_read_cache_local(char *path, size_t psize, size_t chunk_size,
	struct fs_stat *stp, size_t *size)
{
	size_t s;
	struct fs_stat st;
	char *buf = backend_read(path, psize, chunk_size, &st, &s);

	if (buf != NULL) {
		backend_cache_local(path, psize, buf, s, &st, chunk_size);
		if (size)
			*size = s;
		if (stp)
			*stp = st;
	}
	return (buf);
}
