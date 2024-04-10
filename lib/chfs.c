#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <margo.h>
#include "config.h"
#include "ring_types.h"
#include "ring_list.h"
#include "ring_list_rpc.h"
#include "kv_types.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "path.h"
#include "backend.h"
#include "log.h"
#include "chfs.h"
#include "chfs_err.h"

static char chfs_client[PATH_MAX];
static uint32_t chfs_uid, chfs_gid;
static int chfs_chunk_size = 65536;
static size_t chfs_rdma_thresh = 32768;
static int chfs_rpc_timeout_msec = 30000;	/* 30 seconds */
static int chfs_node_list_cache_timeout = 120;	/* 120 seconds */
static int chfs_async_access = 0;
static int chfs_buf_size = 0;
static int initialized = 0;

static ABT_mutex fd_mutex;
static int fd_table_size;
static struct fd_table {
	char *path;
	mode_t mode;
	int cache_flags;
	int chunk_size;
	off_t pos;
	char *buf;
	off_t buf_off, buf_pos;
	int buf_dirty;
	ABT_mutex mutex;
} *fd_table;

void
chfs_set_chunk_size(int chunk_size)
{
	if (chunk_size <= 0)
		return;
	log_info("chfs_set_chunk_size: %d", chunk_size);
	chfs_chunk_size = chunk_size;
}

void
chfs_set_async_access(int enable)
{
	log_info("chfs_set_async_access: %d", enable);
	chfs_async_access = enable;
}

void
chfs_set_buf_size(int buf_size)
{
	log_info("chfs_set_buf_size: %d", buf_size);
	chfs_buf_size = buf_size;
}

void
chfs_set_rdma_thresh(size_t thresh)
{
	log_info("chfs_set_rdma_thresh: %lu", thresh);
	chfs_rdma_thresh = thresh;
}

void
chfs_set_rpc_timeout_msec(int timeout)
{
	log_info("chfs_set_rpc_timeout_msec: %d", timeout);
	chfs_rpc_timeout_msec = timeout;
}

void
chfs_set_node_list_cache_timeout(int timeout)
{
	log_info("chfs_set_node_list_cache_timeout: %d", timeout);
	chfs_node_list_cache_timeout = timeout;
}

static void
fd_table_init()
{
	int i;

	fd_table_size = 100;
	fd_table = malloc(sizeof(*fd_table) * fd_table_size);
	if (fd_table == NULL)
		log_fatal("fd_table_init: no memory");

	for (i = 0; i < fd_table_size; ++i) {
		fd_table[i].path = NULL;
		fd_table[i].buf = NULL;
		ABT_mutex_create(&fd_table[i].mutex);
	}
	ABT_mutex_create(&fd_mutex);
}

static void
fd_table_term()
{
	int i;

	for (i = 0; i < fd_table_size; ++i) {
		free(fd_table[i].path);
		fd_table[i].path = NULL;
		free(fd_table[i].buf);
		fd_table[i].buf = NULL;
		ABT_mutex_free(&fd_table[i].mutex);
	}
	fd_table_size = 0;
	free(fd_table);
	fd_table = NULL;

	ABT_mutex_free(&fd_mutex);
}

static char *
margo_protocol(const char *server)
{
	int s = 0;
	char *proto;

	while (server[s] && server[s] != ':')
		++s;
	if (server[s] != ':')
		return (NULL);
	proto = malloc(s + 1);
	if (proto == NULL)
		return (NULL);
	strncpy(proto, server, s);
	proto[s] = '\0';
	return (proto);
}

static time_t node_list_cache_time;

static int
parse_servers(char *arg, char ***servers)
{
	char **s, **s1, *t, *savep = NULL, *delim = ",";
	int n = 10, i = 0;

	s = malloc(sizeof(*s) * n);
	if (s == NULL)
		return (-1);
	t = strtok_r(arg, delim, &savep);
	while (t != NULL) {
		if (i >= n) {
			n *= 2;
			s1 = realloc(s, sizeof(*s) * n);
			if (s1 == NULL) {
				free(s);
				return (-1);
			}
			s = s1;
		}
		s[i++] = t;
		t = strtok_r(NULL, delim, &savep);
	}
	*servers = s;
	return (i);
}

#define IS_NULL_STRING(str) (str == NULL || str[0] == '\0')

static char *
get_server(int next)
{
	static char *servs = NULL, **servers = NULL;
	static int index = -1, init_index, nservs = -1, err = 0;

	if (err)
		return (NULL);

	if (servs == NULL)
		servs = getenv("CHFS_SERVER");
	if (IS_NULL_STRING(servs))
		goto err;

	if (servers == NULL)
		nservs = parse_servers(servs, &servers);
	if (nservs <= 0)
		goto err;

	if (index == -1)
		init_index = index = random() % nservs;
	else if (next) {
		index = (index + 1) % nservs;
		if (index == init_index)
			goto err;
	}
	return (servers[index]);
 err:
	err = 1;
	return (NULL);
}

int
chfs_initialized()
{
	return (initialized);
}

int
chfs_init(const char *server)
{
	margo_instance_id mid;
	size_t client_size = sizeof(chfs_client);
	hg_addr_t client_addr;
	char *size, *enable, *rdma_thresh, *timeout, *proto, *bpath;
	char *log_priority;
	int max_log_level, g;
	hg_return_t ret;

	if (FLAGS_FROM_MODE(CHFS_O_CACHE) != CHFS_FS_CACHE)
		log_fatal("chfs_init: configuration error, flags mismatch");

	log_priority = getenv("CHFS_LOG_PRIORITY");
	if (!IS_NULL_STRING(log_priority)) {
		max_log_level = log_priority_from_name(log_priority);
		if (max_log_level == -1)
			log_error("%s: invalid log priority", log_priority);
		else
			log_set_priority_max_level(max_log_level);
	}

	srandom(getpid());
	if (IS_NULL_STRING(server))
		server = get_server(0);
	if (IS_NULL_STRING(server))
		log_fatal("chfs_init: no server");
	log_info("chfs_init: server %s", server);

	size = getenv("CHFS_CHUNK_SIZE");
	if (!IS_NULL_STRING(size))
		chfs_set_chunk_size(atoi(size));

	enable = getenv("CHFS_ASYNC_ACCESS");
	if (!IS_NULL_STRING(enable))
		chfs_set_async_access(atoi(enable));

	size = getenv("CHFS_BUF_SIZE");
	if (!IS_NULL_STRING(size))
		chfs_set_buf_size(atoi(size));

	rdma_thresh = getenv("CHFS_RDMA_THRESH");
	if (!IS_NULL_STRING(rdma_thresh))
		chfs_set_rdma_thresh(atol(rdma_thresh));

	timeout = getenv("CHFS_RPC_TIMEOUT_MSEC");
	if (!IS_NULL_STRING(timeout))
		chfs_set_rpc_timeout_msec(atoi(timeout));

	timeout = getenv("CHFS_NODE_LIST_CACHE_TIMEOUT");
	if (!IS_NULL_STRING(timeout))
		chfs_set_node_list_cache_timeout(atoi(timeout));

	bpath = getenv("CHFS_SUBDIR_PATH");
	if (!IS_NULL_STRING(bpath))
		path_set_subdir_path(bpath);

	bpath = getenv("CHFS_BACKEND_PATH");
	if (!IS_NULL_STRING(bpath))
		path_set_backend_path(bpath);

	enable = getenv("CHFS_LOOKUP_LOCAL");
	if (!IS_NULL_STRING(enable))
		ring_list_set_lookup_local(atoi(enable));

	size = getenv("CHFS_LOOKUP_RELAY_GROUP");
	if (!IS_NULL_STRING(size))
		ring_list_set_lookup_relay_group(atoi(size));

	enable = getenv("CHFS_LOOKUP_RELAY_GROUP_AUTO");
	if (!IS_NULL_STRING(enable))
		ring_list_set_lookup_relay_group_auto(atoi(enable));

	while (server != NULL) {
		proto = margo_protocol(server);
		if (proto != NULL)
			break;
		log_notice("%s: no protocol", server);
		server = get_server(1);
	}
	if (server == NULL)
		log_fatal("chfs_init: no protocol");

	mid = margo_init(proto, MARGO_CLIENT_MODE, 1, 0);
	free(proto);
	if (mid == MARGO_INSTANCE_NULL)
		log_fatal("margo_init failed, abort");
	ring_list_init(NULL, NULL);
	ring_list_rpc_init(mid, chfs_rpc_timeout_msec);
	fs_client_init(mid, chfs_rpc_timeout_msec);

	margo_addr_self(mid, &client_addr);
	margo_addr_to_string(mid, chfs_client, &client_size, client_addr);
	margo_addr_free(mid, client_addr);

	ring_list_set_client(chfs_client);
	fd_table_init();
	chfs_uid = getuid();
	chfs_gid = getgid();

	while (server != NULL) {
		ret = ring_list_rpc_node_list(server);
		if (ret == HG_SUCCESS)
			break;
		log_notice("%s: %s", server, HG_Error_to_string(ret));
		server = get_server(1);
	}
	if (server == NULL)
		log_fatal("chfs_init: no server");
	node_list_cache_time = time(NULL);

	if (ring_list_does_lookup_direct())
		chfs_sync(); /* set up all connections */

	initialized = 1;

	log_info("chunk_size %d byte, buf_size %d byte, async_mode %s",
		chfs_chunk_size, chfs_buf_size,
		chfs_async_access ? "enable" : "disable");
	log_info("rdma_thresh %ld byte", chfs_rdma_thresh);
	log_info("rpc_timeout %d msec, node_list_cache_timeout %d sec",
		chfs_rpc_timeout_msec, chfs_node_list_cache_timeout);
	log_info("lookup: %s", ring_list_does_lookup_direct() ? "direct" :
		 ring_list_does_lookup_local() ? "local" :
		 ring_list_get_lookup_relay_group() ? "relay_group" :
		 "unknown");
	if ((g = ring_list_get_lookup_relay_group()))
		log_info("relay_group: %d", g);

	return (0);
}

int
chfs_term_without_sync()
{
	fd_table_term();
	fs_client_term();
	ring_list_term();

	initialized = 0;

	return (0);
}

int
chfs_term()
{
	chfs_sync();
	return (chfs_term_without_sync());
}

int
chfs_size(void)
{
	return (ring_list_size());
}

const char *
chfs_version(void)
{
	return (VERSION);
}

static int
create_fd_unlocked(const char *path, uint32_t mode, int chunk_size)
{
	struct fd_table *tmp;
	int fd, i;

	for (fd = 0; fd < fd_table_size; ++fd)
		if (fd_table[fd].path == NULL)
			break;
	if (fd == fd_table_size) {
		tmp = realloc(fd_table,
			sizeof(*fd_table) * fd_table_size * 2);
		if (tmp == NULL)
			return (-1);
		fd_table = tmp;
		fd_table_size *= 2;
		for (i = fd; i < fd_table_size; ++i) {
			fd_table[i].path = NULL;
			fd_table[i].buf = NULL;
			ABT_mutex_create(&fd_table[i].mutex);
		}
	}
	fd_table[fd].path = strdup(path);
	if (fd_table[fd].path == NULL) {
		log_error("create_fd: %s, no memory", path);
		return (-1);
	}
	if (chfs_buf_size > 0) {
		fd_table[fd].buf = malloc(chfs_buf_size);
		if (fd_table[fd].buf == NULL) {
			free(fd_table[fd].path);
			fd_table[fd].path = NULL;
			log_error("create_fd: %s, no memory", path);
			return (-1);
		}
	}
	fd_table[fd].mode = MODE_MASK(mode);
	fd_table[fd].cache_flags = FLAGS_FROM_MODE(mode);
	fd_table[fd].chunk_size = chunk_size;
	fd_table[fd].pos = 0;
	fd_table[fd].buf_pos = 0;
	fd_table[fd].buf_dirty = 0;
	return (fd);
}

static int
create_fd(const char *path, uint32_t mode, int chunk_size)
{
	int fd;

	ABT_mutex_lock(fd_mutex);
	fd = create_fd_unlocked(path, mode, chunk_size);
	ABT_mutex_unlock(fd_mutex);
	return (fd);
}

static void
clear_fd_table(struct fd_table *tab)
{
	free(tab->path);
	tab->path = NULL;
	free(tab->buf);
	tab->buf = NULL;
}

static int
check_fd_unlocked(int fd)
{
	if (fd < 0 || fd >= fd_table_size) {
		errno = EBADF;
		return (-1);
	}
	if (fd_table[fd].path == NULL) {
		errno = EBADF;
		return (-1);
	}
	return (0);
}

static int
check_fd(int fd)
{
	int r;

	ABT_mutex_lock(fd_mutex);
	r = check_fd_unlocked(fd);
	ABT_mutex_unlock(fd_mutex);
	return (r);
}

static int
clear_fd_unlocked(int fd)
{
	if (check_fd_unlocked(fd))
		return (-1);
	clear_fd_table(&fd_table[fd]);
	return (0);
}

static int
clear_fd(int fd)
{
	int r;

	ABT_mutex_lock(fd_mutex);
	r = clear_fd_unlocked(fd);
	ABT_mutex_unlock(fd_mutex);
	return (r);
}

static struct fd_table *
get_fd_table(int fd)
{
	if (check_fd(fd))
		return (NULL);
	return (&fd_table[fd]);
}

static off_t
fd_pos_set(int fd, off_t pos)
{
	struct fd_table *tab = get_fd_table(fd);

	if (tab == NULL)
		return (-1); /* EBADF */
	if (pos < 0) {
		errno = EINVAL;
		return (-1);
	}
	ABT_mutex_lock(tab->mutex);
	tab->pos = pos;
	ABT_mutex_unlock(tab->mutex);
	return (pos);
}

static off_t
fd_pos_get(int fd)
{
	struct fd_table *tab = get_fd_table(fd);
	off_t pos;

	if (tab == NULL)
		return (-1); /* EBADF */
	ABT_mutex_lock(tab->mutex);
	pos = tab->pos;
	ABT_mutex_unlock(tab->mutex);
	return (pos);
}

static off_t
fd_pos_fetch_and_add(int fd, off_t size)
{
	struct fd_table *tab = get_fd_table(fd);
	off_t pos;

	if (tab == NULL)
		return (-1); /* EBADF */
	ABT_mutex_lock(tab->mutex);
	pos = tab->pos;
	if (pos + size >= 0)
		tab->pos = pos + size;
	else {
		errno = EINVAL;
		pos = -1;
	}
	ABT_mutex_unlock(tab->mutex);
	return (pos);
}

static ssize_t
chfs_pwrite_internal(int fd, const void *buf, size_t size, off_t offset);

static void
fd_flush_unlocked(int fd)
{
	struct fd_table *tab = get_fd_table(fd);

	if (tab->buf_pos > 0 && tab->buf_dirty == 1)
		chfs_pwrite_internal(fd, tab->buf, tab->buf_pos, tab->buf_off);
	tab->buf_pos = tab->buf_dirty = 0;
}

static void
fd_flush(int fd)
{
	struct fd_table *tab = get_fd_table(fd);

	ABT_mutex_lock(tab->mutex);
	fd_flush_unlocked(fd);
	ABT_mutex_unlock(tab->mutex);
}

static int
fd_write(int fd, const char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	size_t ss = 0, s;
	ssize_t buf_off;

	if (tab == NULL || tab->buf == NULL)
		return (0);
	if (size > chfs_buf_size) {
		/* large message, skip buffering */
		fd_flush(fd);
		return (0);
	}
	ABT_mutex_lock(tab->mutex);
	while (size > ss) {
		if (tab->buf_pos == 0)
			tab->buf_off = offset;
		buf_off = offset - tab->buf_off;
		if (buf_off >= 0 && buf_off <= tab->buf_pos) {
			s = chfs_buf_size - buf_off;
			if (s > size - ss)
				s = size - ss;
			if (s > 0) {
				memcpy(&tab->buf[buf_off], buf + ss, s);
				tab->buf_dirty = 1;
				offset += s;
				if (tab->buf_pos < buf_off + s)
					tab->buf_pos = buf_off + s;
				ss += s;
			}
			if (tab->buf_pos == chfs_buf_size)
				fd_flush_unlocked(fd);
		} else
			fd_flush_unlocked(fd);
	}
	ABT_mutex_unlock(tab->mutex);
	return (ss);
}

static ssize_t
chfs_pread_internal(int fd, void *buf, size_t size, off_t offset);

static ssize_t
fd_read(int fd, char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	size_t ss = 0;
	ssize_t s, buf_off;

	if (tab == NULL)
		return (0); /* EBADF */
	if (tab->buf == NULL || size > chfs_buf_size) {
		/* large message, skip buffering */
		return (0);
	}
	ABT_mutex_lock(tab->mutex);
	while (size > ss) {
		if (tab->buf_pos == 0) {
			tab->buf_off = offset;
			s = chfs_pread_internal(fd, tab->buf, chfs_buf_size,
				tab->buf_off);
			if (s > 0)
				tab->buf_pos = s;
			else
				break;
		}
		buf_off = offset - tab->buf_off;
		if (buf_off >= 0 && buf_off < tab->buf_pos) {
			s = tab->buf_pos - buf_off;
			if (s > size - ss)
				s = size - ss;
			memcpy(buf + ss, &tab->buf[buf_off], s);
			offset += s;
			ss += s;
		} else
			fd_flush_unlocked(fd);
	}
	ABT_mutex_unlock(tab->mutex);
	return (ss);
}

static hg_return_t
chfs_rpc_inode_create_data(void *key, size_t key_size, uint32_t mode,
	int chunk_size, const void *buf, size_t size, int *errp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_inode_create_data";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		ret = fs_rpc_inode_create(target, key, key_size, chfs_uid,
			chfs_gid, mode, chunk_size, buf, size, errp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_rpc_inode_create(void *key, size_t key_size, uint32_t mode, int chunk_size,
	int *errp)
{
	return (chfs_rpc_inode_create_data(key, key_size, mode, chunk_size,
			NULL, 0, errp));
}

static hg_return_t
chfs_async_rpc_inode_write(void *key, size_t key_size, const void *buf,
	size_t size, size_t offset, mode_t mode, int chunk_size,
	fs_request_t *rp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "async_rpc_inode_write";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		if (size <= chfs_rdma_thresh)
			ret = fs_async_rpc_inode_write(target, key, key_size,
				buf, size, offset, mode, chunk_size, rp);
		else
			ret = fs_async_rpc_inode_write_rdma(target, key,
				key_size, chfs_client, buf, size, offset, mode,
				chunk_size, rp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_async_rpc_inode_write_wait(size_t *size, int *errp, fs_request_t *rp)
{
	if (*size <= chfs_rdma_thresh)
		return (fs_async_rpc_inode_write_wait(size, errp, rp));
	else
		return (fs_async_rpc_inode_write_rdma_wait(size, errp, rp));
}

static hg_return_t
chfs_rpc_inode_write(void *key, size_t key_size, const void *buf, size_t *size,
	size_t offset, mode_t mode, int chunk_size, int *errp)
{
	hg_return_t ret;
	fs_request_t req;
	static const char diag[] = "rpc_inode_write";

	ret = chfs_async_rpc_inode_write(key, key_size, buf, *size, offset,
		mode, chunk_size, &req);
	if (ret != HG_SUCCESS) {
		log_error("%s (async_rpc): %s", diag, HG_Error_to_string(ret));
		return (ret);
	}
	return (chfs_async_rpc_inode_write_wait(size, errp, &req));
}

static hg_return_t
chfs_async_rpc_inode_read(void *key, size_t key_size, void *buf, size_t size,
	size_t offset, fs_request_t *rp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_async_inode_read";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		if (size <= chfs_rdma_thresh)
			ret = fs_async_rpc_inode_read(target, key, key_size,
				size, offset, rp);
		else
			ret = fs_async_rpc_inode_read_rdma(target, key,
				key_size, chfs_client, buf, size, offset, rp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_async_rpc_inode_read_wait(void *buf, size_t *size, int *errp,
	fs_request_t *rp)
{
	if (*size <= chfs_rdma_thresh)
		return (fs_async_rpc_inode_read_wait(buf, size, errp, rp));
	else
		return (fs_async_rpc_inode_read_rdma_wait(size, errp, rp));
}

static hg_return_t
chfs_rpc_inode_read(void *key, size_t key_size, void *buf, size_t *size,
	size_t offset, int *errp)
{
	hg_return_t ret;
	fs_request_t req;
	static const char diag[] = "rpc_inode_read";

	ret = chfs_async_rpc_inode_read(key, key_size, buf, *size, offset,
		&req);
	if (ret != HG_SUCCESS) {
		log_error("%s (async_rpc): %s", diag, HG_Error_to_string(ret));
		return (ret);
	}
	return (chfs_async_rpc_inode_read_wait(buf, size, errp, &req));
}

static hg_return_t
chfs_rpc_truncate(void *key, size_t key_size, off_t len, int *errp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_inode_truncate";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		ret = fs_rpc_inode_truncate(target, key, key_size, len, errp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_rpc_remove(void *key, size_t key_size, int *errp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_inode_remove";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		ret = fs_rpc_inode_remove(target, key, key_size, errp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_rpc_inode_stat(void *key, size_t key_size, struct fs_stat *st, int *errp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_inode_stat";

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (target == NULL) {
			log_error("%s: no server", diag);
			return (HG_PROTOCOL_ERROR);
		}
		ret = fs_rpc_inode_stat(target, key, key_size, st, errp);
		if (ret == HG_SUCCESS)
			break;

		log_notice("%s: remove %s due to %s", diag, target,
			HG_Error_to_string(ret));
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

int
chfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
	int chunk_size)
{
	char *p = canonical_path(path);
	hg_return_t ret;
	int16_t cache_flags = FLAGS_FROM_MODE(flags);
	uint32_t emode = MODE_FLAGS(mode, cache_flags);
	int fd, err;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0' || chunk_size <= 0) {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	emode |= S_IFREG;
	fd = create_fd(p, emode, chunk_size);
	if (fd < 0) {
		free(p);
		errno = ENOMEM;
		return (-1);
	}
	ret = chfs_rpc_inode_create(p, strlen(p) + 1, emode, chunk_size, &err);
	free(p);
	if (ret == HG_SUCCESS && (err == KV_SUCCESS || err == KV_ERR_NO_SPACE))
		return (fd);

	clear_fd(fd);
	chfs_set_errno(ret, err);
	return (-1);
}

int
chfs_create(const char *path, int32_t flags, mode_t mode)
{
	return (chfs_create_chunk_size(path, flags, mode, chfs_chunk_size));
}

static char *
cache_backend_data(char *path, size_t psize, int index, int chunk_size,
	mode_t *modep, size_t *size)
{
	char *buf = malloc(chunk_size), *bp;
	struct stat sb;
	int s, r, err;
	size_t rr = 0;
	off_t offset = index * chunk_size;
	hg_return_t ret;

	if (buf == NULL)
		return (NULL);
	if ((bp = path_backend(path)) == NULL)
		goto err_free_buf;
	if (stat(bp, &sb) || (s = open(bp, O_RDONLY)) == -1) {
		free(bp);
		goto err_free_buf;
	}
	free(bp);
	r = pread(s, buf, chunk_size, offset);
	while (r > 0) {
		rr += r;
		r = pread(s, buf + rr, chunk_size - rr, offset + rr);
	}
	close(s);
	if (r < 0)
		goto err_free_buf;

	ret = chfs_rpc_inode_write(path, psize, buf, &rr, 0,
		sb.st_mode | CHFS_O_CACHE, chunk_size, &err);
	if (ret != HG_SUCCESS || (err != KV_SUCCESS && err != KV_ERR_NO_SPACE))
		goto err_free_buf;

	if (modep)
		*modep = sb.st_mode;
	if (size)
		*size = rr;
	return (buf);

err_free_buf:
	free(buf);
	return (NULL);
}

int
chfs_open(const char *path, int32_t flags)
{
	char *p = canonical_path(path), *buf;
	struct fs_stat st;
	hg_return_t ret;
	int fd = -1, err;
	size_t psize;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EISDIR;
		return (-1);
	}
	psize = strlen(p) + 1;
	ret = chfs_rpc_inode_stat(p, psize, &st, &err);
	if (ret == HG_SUCCESS && err == KV_ERR_NO_ENTRY) {
		st.chunk_size = chfs_chunk_size;
		if ((buf = cache_backend_data(p, psize, 0, st.chunk_size,
				&st.mode, NULL)) != NULL) {
			free(buf);
			err = KV_SUCCESS;
		}
	}
	if (ret == HG_SUCCESS && err == KV_SUCCESS) {
		if (S_ISDIR(MODE_MASK(st.mode))) {
			free(p);
			errno = EISDIR;
			return (-1);
		}
		fd = create_fd(p, MODE_MASK(st.mode), st.chunk_size);
	}
	else
		chfs_set_errno(ret, err);
	free(p);
	return (fd);
}

#define MAX_INT_SIZE 11

static char *
path_index(const char *path, int index, size_t *size)
{
	char *path_index;
	int path_len;

	if (path == NULL)
		return (NULL);
	path_len = strlen(path) + 1;
	path_index = malloc(path_len + MAX_INT_SIZE);
	if (path_index == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	strcpy(path_index, path);
	if (index == 0) {
		*size = path_len;
		return (path_index);
	}
	sprintf(path_index + path_len, "%d", index);
	*size = path_len + strlen(path_index + path_len) + 1;
	return (path_index);
}

int
chfs_fsync(int fd)
{
	fd_flush(fd);
	return (0);
}

int
chfs_close(int fd)
{
	fd_flush(fd);
	return (clear_fd(fd));
}

static ssize_t
chfs_pwrite_internal_sync(int fd, const char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path;
	int index, local_pos, chunk_size, err;
	uint32_t emode;
	size_t s = size, psize;
	ssize_t ss = 0;
	hg_return_t ret;

	if (tab == NULL)
		return (-1);
	if (size == 0)
		return (0);

	chunk_size = tab->chunk_size;
	emode = MODE_FLAGS(tab->mode, tab->cache_flags);
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	if (local_pos + s > chunk_size)
		s = chunk_size - local_pos;

	path = path_index(tab->path, index, &psize);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_write(path, psize, (void *)buf, &s, local_pos,
		emode, chunk_size, &err);
	free(path);
	if (ret != HG_SUCCESS ||
		(err != KV_SUCCESS && err != KV_ERR_NO_SPACE)) {
		chfs_set_errno(ret, err);
		return (-1);
	} else if (err == KV_ERR_NO_SPACE) {
		err = backend_write_key(tab->path, tab->mode, buf, s, offset);
		if (err != KV_SUCCESS) {
			chfs_set_errno(ret, err);
			return (-1);
		}
	}
	if (size - s > 0) {
		ss = chfs_pwrite_internal_sync(fd, buf + s, size - s,
			offset + s);
		if (ss < 0)
			return (-1);
	}
	return (s + ss);
}

static ssize_t
chfs_pwrite_internal_async(int fd, const char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path, *p;
	int index, local_pos, pos, chunk_size, nchunks, i, err, save_errno = 0;
	uint32_t emode;
	size_t psize, ss = 0;
	struct {
		size_t s;
		fs_request_t r;
	} *req;
	hg_return_t ret = HG_SUCCESS;

	if (tab == NULL)
		return (-1);
	chunk_size = tab->chunk_size;
	emode = MODE_FLAGS(tab->mode, tab->cache_flags);
	p = strdup(tab->path);
	if (p == NULL)
		return (-1);

	if (size == 0) {
		free(p);
		return (0);
	}
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	nchunks = (size + local_pos + chunk_size - 1) / chunk_size;
	req = malloc(sizeof(*req) * nchunks);
	if (req == NULL) {
		free(p);
		errno = ENOMEM;
		return (-1);
	}

	req[0].s = size;
	if (local_pos + req[0].s > chunk_size)
		req[0].s = chunk_size - local_pos;
	pos = local_pos;
	for (i = 0; i < nchunks; ++i) {
		path = path_index(p, index + i, &psize);
		if (path == NULL)
			break;
		ret = chfs_async_rpc_inode_write(path, psize, buf + ss,
			req[i].s, pos, emode, chunk_size, &req[i].r);
		free(path);
		if (ret != HG_SUCCESS)
			break;
		ss += req[i].s;
		if (i < nchunks - 1) {
			req[i + 1].s = size - ss;
			if (req[i + 1].s > chunk_size)
				req[i + 1].s = chunk_size;
		}
		pos = 0;
	}
	free(p);
	if (i < nchunks) {
		for (--i; i >= 0; --i)
			chfs_async_rpc_inode_write_wait(&req[i].s, &err,
				&req[i].r);
		free(req);
		if (ret != HG_SUCCESS)
			chfs_set_errno(ret, KV_SUCCESS);
		return (-1);
	}

	ss = 0;
	for (i = 0; i < nchunks; ++i) {
		ret = chfs_async_rpc_inode_write_wait(&req[i].s, &err,
			&req[i].r);
		if (ret != HG_SUCCESS ||
			(err != KV_SUCCESS && err != KV_ERR_NO_SPACE)) {
			chfs_set_errno(ret, err);
			if (save_errno == 0)
				save_errno = errno;
		} else if (err == KV_ERR_NO_SPACE) {
			err = backend_write_key(tab->path, tab->mode, buf + ss,
				req[i].s, offset + ss);
			if (save_errno == 0) {
				chfs_set_errno(ret, err);
				save_errno = errno;
			}
			if (err == KV_SUCCESS || err == KV_ERR_PARTIAL_WRITE)
				ss += req[i].s;
		} else
			ss += req[i].s;
	}
	free(req);
	if (save_errno) {
		errno = save_errno;
		return (-1);
	}
	return (ss);
}

ssize_t
chfs_pwrite_internal(int fd, const void *buf, size_t size, off_t offset)
{
	if (chfs_async_access)
		return (chfs_pwrite_internal_async(fd, buf, size, offset));
	return (chfs_pwrite_internal_sync(fd, buf, size, offset));
}

ssize_t
chfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	ssize_t s;

	s = fd_write(fd, buf, size, offset);
	if (s > 0)
		return (s);
	return (chfs_pwrite_internal(fd, buf, size, offset));
}

ssize_t
chfs_write(int fd, const void *buf, size_t size)
{
	off_t pos;

	pos = fd_pos_fetch_and_add(fd, size);
	/* dont care even if EBADF */
	return (chfs_pwrite(fd, buf, size, pos));
}

static ssize_t
chfs_pread_internal_sync(int fd, char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	char *path, *bdata;
	hg_return_t ret;
	int index, local_pos, chunk_size, err;
	size_t s = size, psize, cs;
	ssize_t ss = 0;

	if (tab == NULL)
		return (-1);

	chunk_size = tab->chunk_size;
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	path = path_index(tab->path, index, &psize);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_read(path, psize, buf, &s, local_pos, &err);
	if (ret == HG_SUCCESS && err == KV_ERR_NO_ENTRY &&
		(bdata = cache_backend_data(path, psize, index, chunk_size,
			NULL, &cs)) != NULL) {
		if (cs > local_pos) {
			if (local_pos + s > cs)
				s = cs - local_pos;
			memcpy(buf, bdata + local_pos, s);
		} else
			s = 0;
		free(bdata);
		err = KV_SUCCESS;
	}
	free(path);
	if (ret != HG_SUCCESS ||
		(err != KV_SUCCESS && err != KV_ERR_NO_ENTRY)) {
		chfs_set_errno(ret, err);
		return (-1);
	} else if (err == KV_ERR_NO_ENTRY)
		s = 0;

	if (s == 0)
		return (0);

	if (local_pos + s < chunk_size)
		return (s);
	if (size - s > 0) {
		ss = chfs_pread_internal_sync(fd, buf + s, size - s,
			offset + s);
		if (ss < 0)
			ss = 0;
	}
	return (s + ss);
}

static ssize_t
chfs_pread_internal_async(int fd, char *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	char *path, *p, *bdata;
	int index, local_pos, pos, chunk_size, nchunks, i, err;
	size_t psize, s, ss = 0, sss, ssss, may_hole;
	struct {
		size_t s;
		fs_request_t r;
	} *req;
	hg_return_t ret = HG_SUCCESS, save_ret = HG_SUCCESS;

	if (tab == NULL)
		return (-1);
	chunk_size = tab->chunk_size;
	p = strdup(tab->path);
	if (p == NULL)
		return (-1);

	if (size == 0) {
		free(p);
		return (0);
	}
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	nchunks = (size + local_pos + chunk_size - 1) / chunk_size;
	req = malloc(sizeof(*req) * nchunks);
	if (req == NULL) {
		free(p);
		errno = ENOMEM;
		return (-1);
	}

	req[0].s = size;
	if (local_pos + req[0].s > chunk_size)
		req[0].s = chunk_size - local_pos;
	pos = local_pos;
	for (i = 0; i < nchunks; ++i) {
		path = path_index(p, index + i, &psize);
		if (path == NULL)
			break;
		ret = chfs_async_rpc_inode_read(path, psize, buf + ss, req[i].s,
			pos, &req[i].r);
		free(path);
		if (ret != HG_SUCCESS)
			break;
		ss += req[i].s;
		if (i < nchunks - 1) {
			req[i + 1].s = size - ss;
			if (req[i + 1].s > chunk_size)
				req[i + 1].s = chunk_size;
		}
		pos = 0;
	}
	if (i < nchunks) {
		for (--i; i >= 0; --i)
			chfs_async_rpc_inode_read_wait(NULL, &req[i].s, &err,
				&req[i].r);
		free(req);
		free(p);
		if (ret != HG_SUCCESS)
			chfs_set_errno(ret, KV_SUCCESS);
		return (-1);
	}

	pos = local_pos;
	ss = sss = may_hole = 0;
	for (i = 0; i < nchunks; ++i, pos = 0) {
		s = req[i].s;
		ret = chfs_async_rpc_inode_read_wait(buf + ss, &s, &err,
			&req[i].r);
		if (ret != HG_SUCCESS) {
			if (save_ret == HG_SUCCESS)
				save_ret = ret;
		} else if (err == KV_ERR_NO_ENTRY) {
			path = path_index(p, index + i, &psize);
			if (path == NULL)
				break;
			bdata = cache_backend_data(path, psize, index + i,
				chunk_size, NULL, &ssss);
			free(path);
			if (bdata) {
				if (ssss > pos) {
					if (req[i].s > ssss - pos)
						req[i].s = ssss - pos;
					memcpy(buf + ss, bdata + pos, req[i].s);
					sss += req[i].s;
				} else
					req[i].s = 0;
				free(bdata);
			} else
				may_hole += req[i].s;
		} else if (err == KV_SUCCESS) {
			if (may_hole > 0) {
				memset(buf + ss - may_hole, 0, may_hole);
				sss += may_hole;
			}
			sss += s;
			may_hole = req[i].s - s;
		}
		ss += req[i].s;
	}
	free(req);
	free(p);
	if (save_ret != HG_SUCCESS) {
		chfs_set_errno(save_ret, KV_SUCCESS);
		return (-1);
	}
	return (sss);
}

ssize_t
chfs_pread_internal(int fd, void *buf, size_t size, off_t offset)
{
	if (chfs_async_access)
		return (chfs_pread_internal_async(fd, buf, size, offset));
	return (chfs_pread_internal_sync(fd, buf, size, offset));
}

ssize_t
chfs_pread(int fd, void *buf, size_t size, off_t offset)
{
	ssize_t s;

	s = fd_read(fd, buf, size, offset);
	if (s > 0)
		return (s);
	return (chfs_pread_internal(fd, buf, size, offset));
}

ssize_t
chfs_read(int fd, void *buf, size_t size)
{
	off_t pos, pos1;
	ssize_t s;

	pos = fd_pos_get(fd);
	/* dont care even if EBADF */
	s = chfs_pread(fd, buf, size, pos);
	if (s > 0) {
		pos1 = fd_pos_fetch_and_add(fd, s);
		if (pos != pos1) {
			struct fd_table *tab = get_fd_table(fd);

			log_notice("chfs_read: %s: read conflict "
				"(offset %ld size %ld)",
				tab->path, pos, size);
		}
	}
	return (s);
}

off_t
chfs_seek(int fd, off_t off, int whence)
{
	struct fd_table *tab = get_fd_table(fd);
	off_t pos = -1;
	struct stat sb;

	if (tab == NULL)
		return (-1);
	switch (whence) {
	case SEEK_SET:
		pos = fd_pos_set(fd, off);
		break;
	case SEEK_CUR:
		pos = fd_pos_fetch_and_add(fd, off);
		if (pos >= 0)
			pos = fd_pos_get(fd);
		break;
	case SEEK_END:
		pos = fd_pos_get(fd);
		if (chfs_stat(tab->path, &sb) == 0) {
			if (pos < sb.st_size)
				pos = sb.st_size;
			pos = fd_pos_set(fd, pos + off);
		}
	default:
		break;
	}
	if (pos < 0)
		errno = EINVAL;
	return (pos);
}

static int
chfs_unlink_chunk_all(char *path, int index);

#define UNLINK_CHUNK_SIZE	10

int
chfs_unlink(const char *path)
{
	char *p = canonical_path(path);
	hg_return_t ret;
	int err, i;
	size_t psize;
	void *pi;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	ret = chfs_rpc_remove(p, strlen(p) + 1, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		free(p);
		chfs_set_errno(ret, err);
		return (-1);
	}
	for (i = 1; i < UNLINK_CHUNK_SIZE; ++i) {
		pi = path_index(p, i, &psize);
		if (pi == NULL)
			break;
		ret = chfs_rpc_remove(pi, psize, &err);
		free(pi);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			break;
	}
	if (i == UNLINK_CHUNK_SIZE)
		chfs_unlink_chunk_all(p, UNLINK_CHUNK_SIZE);
	free(p);
	return (0);
}

int
chfs_mkdir(const char *path, mode_t mode)
{
	char *p = canonical_path(path);
	hg_return_t ret;
	int err;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	mode |= S_IFDIR;
	ret = chfs_rpc_inode_create(p, strlen(p) + 1, mode, 0, &err);
	free(p);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	return (0);
}

int
chfs_rmdir(const char *path)
{
	char *p = canonical_path(path);
	hg_return_t ret;
	int err;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	/* XXX check child entries */
	ret = chfs_rpc_remove(p, strlen(p) + 1, &err);
	free(p);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	return (0);
}

int
chfs_symlink(const char *target, const char *path)
{
	char *p;
	mode_t mode;
	hg_return_t ret;
	int err, len;

	if (target == NULL) {
		errno = ENOENT;
		return (-1);
	}
	p = canonical_path(path);
	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	mode = 0777 | S_IFLNK;
	len = strlen(target);
	ret = chfs_rpc_inode_create_data(p, strlen(p) + 1, mode, len + 1,
		target, len + 1, &err);
	free(p);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	return (0);
}

int
chfs_readlink(const char *path, char *buf, size_t size)
{
	char *p = canonical_path(path), *bp;
	size_t s = size;
	hg_return_t ret;
	int err;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	ret = chfs_rpc_inode_read(p, strlen(p) + 1, buf, &s, 0, &err);
	if (ret == HG_SUCCESS && err == KV_ERR_NO_ENTRY &&
		((bp = path_backend(p)) != NULL)) {
		s = readlink(bp, buf, size);
		free(bp);
		free(p);
		return (s);
	}
	free(p);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	if (s > 1 && buf[s - 1] == '\0')
		--s;
	return (s);
}

static void
root_stat(struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFDIR | 0755;
}

/* Number of 512B blocks */
#define NUM_BLOCKS(size) ((size + 511) / 512)

int
chfs_stat(const char *path, struct stat *st)
{
	char *p = canonical_path(path), *bp;
	struct fs_stat sb;
	size_t psize;
	void *pi;
	hg_return_t ret;
	int err, i, j, r;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		root_stat(st);
		free(p);
		return (0);
	}
	ret = chfs_rpc_inode_stat(p, strlen(p) + 1, &sb, &err);
	if (ret == HG_SUCCESS && err == KV_ERR_NO_ENTRY) {
		bp = path_backend(p);
		if (bp != NULL) {
			r = lstat(bp, st);
			free(bp);
			free(p);
			return (r);
		}
	}
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		free(p);
		chfs_set_errno(ret, err);
		return (-1);
	}
	st->st_mode = MODE_MASK(sb.mode);
	st->st_uid = sb.uid;
	st->st_gid = sb.gid;
	st->st_size = sb.size;
	st->st_mtim = sb.mtime;
	st->st_ctim = sb.ctime;
	st->st_nlink = 1;
	st->st_blksize = sb.chunk_size;
	st->st_blocks = NUM_BLOCKS(st->st_size);
	if (!S_ISREG(st->st_mode) || sb.size < sb.chunk_size) {
		free(p);
		return (0);
	}
	for (j = 0, i = 1;;) {
		pi = path_index(p, j + i, &psize);
		if (pi == NULL)
			break;
		ret = chfs_rpc_inode_stat(pi, psize, &sb, &err);
		free(pi);
		if (ret != HG_SUCCESS)
			break;
		if (err != KV_SUCCESS) {
			if (i == 1)
				break;
			i /= 2;
			st->st_size += sb.chunk_size * i;
			j += i;
			i = 1;
			continue;
		}
		if (sb.size == 0 || sb.size < sb.chunk_size) {
			st->st_size += sb.chunk_size * (i - 1) + sb.size;
			break;
		}
		i *= 2;
	}
	st->st_blocks = NUM_BLOCKS(st->st_size);
	free(p);
	return (0);
}

int
chfs_truncate(const char *path, off_t len)
{
	char *p;
	struct fs_stat sb;
	size_t psize, index, local_len;
	void *pi;
	hg_return_t ret;
	mode_t mode;
	int err, i;

	if (len < 0) {
		errno = EINVAL;
		return (-1);
	}
	p = canonical_path(path);
	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		free(p);
		errno = EINVAL;
		return (-1);
	}
	ret = chfs_rpc_inode_stat(p, strlen(p) + 1, &sb, &err);
	mode = MODE_MASK(sb.mode);
	if (ret != HG_SUCCESS || err != KV_SUCCESS || !S_ISREG(mode)) {
		free(p);
		chfs_set_errno(ret, err);
		if (errno == 0 && !S_ISREG(sb.mode))
			errno = EINVAL;
		return (-1);
	}
	index = len / sb.chunk_size;
	local_len = len % sb.chunk_size;

	pi = path_index(p, index, &psize);
	ret = chfs_rpc_truncate(pi, psize, local_len, &err);
	free(pi);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		free(p);
		chfs_set_errno(ret, err);
		return (-1);
	}
	for (i = index + 1;; ++i) {
		pi = path_index(p, i, &psize);
		if (pi == NULL)
			break;
		ret = chfs_rpc_remove(pi, psize, &err);
		free(pi);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			break;
	}
	free(p);
	return (0);
}

static int
chfs_node_list_cache_is_timeout()
{
	return (chfs_node_list_cache_timeout > 0 &&
	    time(NULL) - node_list_cache_time > chfs_node_list_cache_timeout);
}

static ABT_mutex_memory rl_mutex_mem = ABT_MUTEX_INITIALIZER;
static ABT_cond_memory rl_cond_mem = ABT_COND_INITIALIZER;
static int rl_count = 0;

static void
update_node_list(void)
{
	node_list_t node_list;
	int i, ii, di;
	hg_return_t ret;

	if (chfs_node_list_cache_is_timeout()) {
		log_debug("chfs_ring_list_copy: node_list cache timeout");
		ring_list_copy(&node_list);
		di = random() % node_list.n;
		for (i = 0; i < node_list.n; ++i) {
			ii = (i + di) % node_list.n;
			if (node_list.s[ii].address == NULL)
				continue;
			ret = ring_list_rpc_node_list(node_list.s[ii].address);
			if (ret == HG_SUCCESS)
				break;
			log_notice("%s: %s", node_list.s[ii].address,
				HG_Error_to_string(ret));
		}
		if (i == node_list.n)
			log_fatal("chfs_ring_list_copy: no server");
		ring_list_copy_free(&node_list);
		node_list_cache_time = time(NULL);
	}
}

static void
chfs_ring_list_copy(node_list_t *node_list)
{
	ABT_mutex mutex = ABT_MUTEX_MEMORY_GET_HANDLE(&rl_mutex_mem);
	ABT_cond cond = ABT_COND_MEMORY_GET_HANDLE(&rl_cond_mem);

	ABT_mutex_lock(mutex);
	++rl_count;
	if (rl_count == 1) {
		ABT_mutex_unlock(mutex);
		update_node_list();
		ABT_mutex_lock(mutex);
		rl_count = 0;
		ABT_cond_broadcast(cond);
	} else
		ABT_cond_wait(cond, mutex);
	ABT_mutex_unlock(mutex);
	ring_list_copy(node_list);
}

static int
backend_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t))
{
	DIR *dp;
	struct dirent *dent;
	struct stat sb;

	dp = opendir(path);
	if (dp == NULL)
		return (-1);
	while ((dent = readdir(dp)) != NULL) {
		memset(&sb, 0, sizeof(sb));
		sb.st_ino = dent->d_ino;
		sb.st_mode = dent->d_type << 12;
		if (filler(buf, dent->d_name, &sb, 0))
			break;
	}
	closedir(dp);
	return (0);
}

int
chfs_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t))
{
	char *p = canonical_path(path), *bp;
	node_list_t node_list;
	hg_return_t ret;
	int err, i, ii, di;

	if (p == NULL)
		return (-1);

	bp = path_backend(p);
	if (bp != NULL) {
		backend_readdir(bp, buf, filler);
		free(bp);
	}
	chfs_ring_list_copy(&node_list);
	di = random() % node_list.n;
	for (i = 0; i < node_list.n; ++i) {
		ii = (i + di) % node_list.n;
		if (node_list.s[ii].address == NULL)
			continue;
		ret = fs_rpc_readdir(node_list.s[ii].address, p, buf, filler,
			&err);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			continue;
	}
	ring_list_copy_free(&node_list);
	free(p);
	return (0);
}

int
chfs_readdir_index(const char *path, int index, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t))
{
	char *p = canonical_path(path), *target;
	int err;

	if (p == NULL)
		return (-1);
	target = ring_list_lookup_index(index);
	if (target && filler)
		fs_rpc_readdir_replica(target, p, buf, filler, &err);
	free(target);
	free(p);
	return (0);
}

static int
chfs_unlink_chunk_all(char *p, int index)
{
	node_list_t node_list;
	hg_return_t ret;
	int i, ii, di;

	chfs_ring_list_copy(&node_list);
	di = random() % node_list.n;
	for (i = 0; i < node_list.n; ++i) {
		ii = (i + di) % node_list.n;
		if (node_list.s[ii].address == NULL)
			continue;
		ret = fs_async_rpc_inode_unlink_chunk_all(
				node_list.s[ii].address, p, index);
		if (ret != HG_SUCCESS)
			continue;
	}
	ring_list_copy_free(&node_list);
	return (0);
}

void
chfs_sync()
{
	node_list_t nlist;
	hg_return_t ret;
	struct {
		fs_request_t req;
		int need_wait;
	} *r;
	int i, ii, di;
	static const char diag[] = "chfs_sync";

	chfs_ring_list_copy(&nlist);
	r = malloc(sizeof(*r) * nlist.n);
	if (r == NULL) {
		log_error("%s (malloc): no memory for %ld bytes", diag,
			sizeof(*r) * nlist.n);
		goto ring_list_free;
	}
	di = random() % nlist.n;
	for (i = 0; i < nlist.n; ++i) {
		ii = (i + di) % nlist.n;
		r[ii].need_wait = 0;
		if (nlist.s[ii].address == NULL)
			continue;
		ret = fs_async_rpc_inode_sync_request(nlist.s[ii].address,
			&r[ii].req);
		if (ret != HG_SUCCESS) {
			log_notice("%s (sync_request): %s, %s", diag,
				nlist.s[ii].address, HG_Error_to_string(ret));
			continue;
		}
		r[ii].need_wait = 1;
	}
	for (i = 0; i < nlist.n; ++i) {
		ii = (i + di) % nlist.n;
		if (r[ii].need_wait == 0)
			continue;
		ret = fs_async_rpc_inode_sync_wait(&r[ii].req);
		if (ret != HG_SUCCESS) {
			log_notice("%s (sync_wait): %s, %s", diag,
				nlist.s[ii].address, HG_Error_to_string(ret));
			continue;
		}
	}
	free(r);
ring_list_free:
	ring_list_copy_free(&nlist);
}

static int stagein_bufsize = 1024 * 1024;

void
chfs_set_stagein_buf_size(int buf_size)
{
	log_info("chfs_set_stagein_buf_size: %d", buf_size);
	stagein_bufsize = buf_size;
}

static int
stagein_reg(const char *src, const char *dst, mode_t mode)
{
	int s, d, r, rr, st = -1;
	char *buf;
	static const char diag[] = "chfs_stagein";

	buf = malloc(stagein_bufsize);
	if (buf == NULL) {
		log_error("%s: no memory (%d bytes)", diag, stagein_bufsize);
		errno = ENOMEM;
		return (-1);
	}
	if ((s = open(src, O_RDONLY)) == -1)
		goto free_buf;

	d = chfs_create(dst, O_WRONLY | CHFS_O_CACHE, mode);
	if (d < 0)
		goto close_s;

	r = read(s, buf, stagein_bufsize);
	while (r > 0) {
		rr = chfs_write(d, buf, r);
		if (rr < 0 || r != rr)
			break;
		r = read(s, buf, stagein_bufsize);
	}
	if (r == 0)
		st = 0;

	chfs_close(d);
close_s:
	close(s);
free_buf:
	free(buf);

	return (st);
}

int
chfs_stagein(const char *path)
{
	char *src = canonical_path(path), *dst;
	char sym_buf[PATH_MAX];
	struct stat sb;
	int st = -1;

	if (src == NULL)
		return (-1);
	if (src[0] == '\0')
		return (0);

	dst = path_subdir(src);
	if (dst == NULL) {
		errno = ENOMEM;
		goto free_src;
	}
	if (lstat(src, &sb) == -1)
		goto free_dst;

	if (S_ISREG(sb.st_mode))
		st = stagein_reg(src, dst, sb.st_mode);
	else if (S_ISDIR(sb.st_mode)) {
		st = chfs_mkdir(dst, sb.st_mode | 0700 | CHFS_O_CACHE);
		if (st == -1 && errno == EEXIST)
			st = 0;
	} else if (S_ISLNK(sb.st_mode)) {
		st = readlink(src, sym_buf, sizeof sym_buf);
		if (st > 0) {
			sym_buf[st] = '\0';
			st = chfs_symlink(sym_buf, dst);
		}
	} else
		errno = ENOTSUP;

free_dst:
	free(dst);
free_src:
	free(src);

	return (st);
}
