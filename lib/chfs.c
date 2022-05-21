#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
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
#include "log.h"
#include "chfs.h"
#include "chfs_err.h"

#define ASYNC_ACCESS

static char chfs_client[PATH_MAX];
static uint32_t chfs_uid, chfs_gid;
static int chfs_chunk_size = 4096;
static int chfs_rdma_thresh = 2048;
static int chfs_rpc_timeout_msec = 0;		/* no timeout */
static int chfs_node_list_cache_timeout = 120;	/* 120 seconds */

static ABT_mutex fd_mutex;
static int fd_table_size;
static struct fd_table {
	char *path;
	mode_t mode;
	int chunk_size, pos;
	int ref, closed;
} *fd_table;

void
chfs_set_chunk_size(int chunk_size)
{
	log_info("chfs_set_chunk_size: %d", chunk_size);
	chfs_chunk_size = chunk_size;
}

void
chfs_set_rdma_thresh(int thresh)
{
	log_info("chfs_set_rdma_thresh: %d", thresh);
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

	for (i = 0; i < fd_table_size; ++i)
		fd_table[i].path = NULL;
	ABT_mutex_create(&fd_mutex);
}

static void
fd_table_term()
{
	int i;

	for (i = 0; i < fd_table_size; ++i) {
		free(fd_table[i].path);
		fd_table[i].path = NULL;
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

	if (index == -1) {
		srandom(getpid());
		init_index = index = random() % nservs;
	} else if (next) {
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
chfs_init(const char *server)
{
	margo_instance_id mid;
	size_t client_size = sizeof(chfs_client);
	hg_addr_t client_addr;
	char *chunk_size, *rdma_thresh, *timeout, *proto;
	char *log_priority;
	int max_log_level;
	hg_return_t ret;

	log_priority = getenv("CHFS_LOG_PRIORITY");
	if (!IS_NULL_STRING(log_priority)) {
		max_log_level = log_priority_from_name(log_priority);
		if (max_log_level == -1)
			log_error("%s: invalid log priority", log_priority);
		else
			log_set_priority_max_level(max_log_level);
	}

	if (IS_NULL_STRING(server))
		server = get_server(0);
	if (IS_NULL_STRING(server))
		log_fatal("chfs_init: no server");
	log_info("chfs_init: server %s", server);

	chunk_size = getenv("CHFS_CHUNK_SIZE");
	if (!IS_NULL_STRING(chunk_size))
		chfs_set_chunk_size(atoi(chunk_size));

	rdma_thresh = getenv("CHFS_RDMA_THRESH");
	if (!IS_NULL_STRING(rdma_thresh))
		chfs_set_rdma_thresh(atoi(rdma_thresh));

	timeout = getenv("CHFS_RPC_TIMEOUT_MSEC");
	if (!IS_NULL_STRING(timeout))
		chfs_set_rpc_timeout_msec(atoi(timeout));

	timeout = getenv("CHFS_NODE_LIST_CACHE_TIMEOUT");
	if (!IS_NULL_STRING(timeout))
		chfs_set_node_list_cache_timeout(atoi(timeout));

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

	return (0);
}

int
chfs_term()
{
	fd_table_term();
	fs_client_term();
	ring_list_term();

	return (0);
}

const char *
chfs_version(void)
{
	return (VERSION);
}

static int
create_fd_unlocked(const char *path, mode_t mode, int chunk_size)
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
		for (i = fd; i < fd_table_size; ++i)
			fd_table[i].path = NULL;
	}
	fd_table[fd].path = strdup(path);
	if (fd_table[fd].path == NULL) {
		log_error("create_fd: %s, no memory", path);
		return (-1);
	}
	fd_table[fd].mode = mode;
	fd_table[fd].chunk_size = chunk_size;
	fd_table[fd].pos = 0;
	fd_table[fd].ref = 0;
	fd_table[fd].closed = 0;
	return (fd);
}

static int
create_fd(const char *path, mode_t mode, int chunk_size)
{
	int fd;

	ABT_mutex_lock(fd_mutex);
	fd = create_fd_unlocked(path, mode, chunk_size);
	ABT_mutex_unlock(fd_mutex);
	return (fd);
}

static void
clear_fd_table_unlocked(struct fd_table *tab)
{
	free(tab->path);
	tab->path = NULL;
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
clear_fd_unlocked(int fd)
{
	if (check_fd_unlocked(fd))
		return (-1);
	if (fd_table[fd].ref > 0)
		fd_table[fd].closed = 1;
	else
		clear_fd_table_unlocked(&fd_table[fd]);
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
get_fd_table_unlocked(int fd)
{
	if (check_fd_unlocked(fd))
		return (NULL);
	if (fd_table[fd].closed) {
		errno = EBADF;
		return (NULL);
	}
	++fd_table[fd].ref;
	return (&fd_table[fd]);
}

static struct fd_table *
get_fd_table(int fd)
{
	struct fd_table *tab;

	ABT_mutex_lock(fd_mutex);
	tab = get_fd_table_unlocked(fd);
	ABT_mutex_unlock(fd_mutex);
	return (tab);
}

static void
release_fd_table_unlocked(struct fd_table *tab)
{
	if (tab == NULL)
		return;
	--tab->ref;
	if (tab->closed == 0 || tab->ref > 0)
		return;
	clear_fd_table_unlocked(tab);
}

static void
release_fd_table(struct fd_table *tab)
{
	ABT_mutex_lock(fd_mutex);
	release_fd_table_unlocked(tab);
	ABT_mutex_unlock(fd_mutex);
}

static hg_return_t
chfs_rpc_inode_create_data(void *key, size_t key_size, mode_t mode,
	int chunk_size, const void *buf, size_t size, int *errp)
{
	char *target;
	hg_return_t ret;
	static const char diag[] = "rpc_inode_create_data";

	target = ring_list_get_local_server();
	if (target) {
		ret = fs_rpc_inode_create(target, key, key_size, chfs_uid,
			chfs_gid, mode, chunk_size, buf, size, errp);
		free(target);
		if (ret == HG_SUCCESS)
			return (ret);
	}
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
chfs_rpc_inode_create(void *key, size_t key_size, mode_t mode, int chunk_size,
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
		if (size < chfs_rdma_thresh)
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
	if (*size < chfs_rdma_thresh)
		return (fs_async_rpc_inode_write_wait(size, errp, rp));
	else
		return (fs_async_rpc_inode_write_rdma_wait(size, errp, rp));
}

#ifndef ASYNC_ACCESS
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
#endif

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
		if (size < chfs_rdma_thresh)
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
	if (*size < chfs_rdma_thresh)
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

static hg_return_t
chfs_rpc_inode_stat_local(void *key, size_t key_size, struct fs_stat *st,
	int *errp)
{
	char *target;
	hg_return_t ret;

	target = ring_list_get_local_server();
	if (target) {
		ret = fs_rpc_inode_stat(target, key, key_size, st, errp);
		free(target);
		if (ret == HG_SUCCESS)
			return (ret);
	}
	return (chfs_rpc_inode_stat(key, key_size, st, errp));
}

int
chfs_create_chunk_size(const char *path, int32_t flags, mode_t mode,
	int chunk_size)
{
	char *p = canonical_path(path);
	hg_return_t ret;
	int fd, err;

	if (p == NULL)
		return (-1);
	mode |= S_IFREG;
	fd = create_fd(p, mode, chunk_size);
	if (fd < 0) {
		free(p);
		errno = ENOMEM;
		return (-1);
	}
	ret = chfs_rpc_inode_create(p, strlen(p) + 1, mode, chunk_size, &err);
	free(p);
	if (ret == HG_SUCCESS && err == KV_SUCCESS)
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

int
chfs_open(const char *path, int32_t flags)
{
	char *p = canonical_path(path);
	struct fs_stat st;
	hg_return_t ret;
	int fd, err;

	if (p == NULL)
		return (-1);
	ret = chfs_rpc_inode_stat_local(p, strlen(p) + 1, &st, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		free(p);
		chfs_set_errno(ret, err);
		return (-1);
	}
	fd = create_fd(p, st.mode, st.chunk_size);
	free(p);
	if (fd >= 0)
		return (fd);
	errno = ENOMEM;
	return (-1);
}

#define MAX_INT_SIZE 11

static void *
path_index(const char *path, int index, size_t *size)
{
	void *path_index;
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
	return (0);
}

int
chfs_close(int fd)
{
	return (clear_fd(fd));
}

#ifndef ASYNC_ACCESS
ssize_t
chfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path;
	int index, local_pos, chunk_size, err;
	mode_t mode;
	size_t s = size, psize;
	ssize_t ss = 0;
	hg_return_t ret;

	if (tab == NULL)
		return (-1);

	chunk_size = tab->chunk_size;
	mode = tab->mode;
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	if (local_pos + s > chunk_size)
		s = chunk_size - local_pos;

	path = path_index(tab->path, index, &psize);
	release_fd_table(tab);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_write(path, psize, (void *)buf, &s, local_pos,
		mode, chunk_size, &err);
	free(path);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	if (size - s > 0) {
		ss = chfs_pwrite(fd, buf + s, size - s, offset + s);
		if (ss < 0)
			return (-1);
	}
	return (s + ss);
}

#else

ssize_t
chfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path, *p;
	int index, local_pos, pos, chunk_size, nchunks, i, err, save_errno = 0;
	mode_t mode;
	size_t psize, ss = 0;
	struct {
		size_t s;
		fs_request_t r;
	} *req;
	hg_return_t ret = HG_SUCCESS;

	if (tab == NULL)
		return (-1);
	chunk_size = tab->chunk_size;
	mode = tab->mode;
	p = strdup(tab->path);
	release_fd_table(tab);
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
			req[i].s, pos, mode, chunk_size, &req[i].r);
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
		if (ret != HG_SUCCESS || err != KV_SUCCESS) {
			chfs_set_errno(ret, err);
			if (save_errno == 0)
				save_errno = errno;
		}
		ss += req[i].s;
	}
	free(req);
	if (save_errno) {
		errno = save_errno;
		return (-1);
	}
	return (ss);
}
#endif

ssize_t
chfs_write(int fd, const void *buf, size_t size)
{
	struct fd_table *tab = get_fd_table(fd);
	ssize_t s;

	s = chfs_pwrite(fd, buf, size, tab->pos);
	if (s > 0)
		tab->pos += s;
	release_fd_table(tab);
	return (s);
}

#ifndef ASYNC_ACCESS
ssize_t
chfs_pread(int fd, void *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path;
	int index, local_pos, chunk_size, ret, err;
	size_t s = size, psize;
	ssize_t ss = 0;

	if (tab == NULL)
		return (-1);

	chunk_size = tab->chunk_size;
	index = offset / chunk_size;
	local_pos = offset % chunk_size;

	path = path_index(tab->path, index, &psize);
	release_fd_table(tab);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_read(path, psize, buf, &s, local_pos, &err);
	free(path);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	if (s == 0)
		return (0);

	if (local_pos + s < chunk_size)
		return (s);
	if (size - s > 0) {
		ss = chfs_pread(fd, buf + s, size - s, offset + s);
		if (ss < 0)
			ss = 0;
	}
	return (s + ss);
}

#else

ssize_t
chfs_pread(int fd, void *buf, size_t size, off_t offset)
{
	struct fd_table *tab = get_fd_table(fd);
	void *path, *p;
	int index, local_pos, pos, chunk_size, nchunks, i, err;
	size_t psize, ss = 0;
	struct {
		size_t s;
		fs_request_t r;
	} *req;
	hg_return_t ret = HG_SUCCESS, save_ret = HG_SUCCESS;

	if (tab == NULL)
		return (-1);
	chunk_size = tab->chunk_size;
	p = strdup(tab->path);
	release_fd_table(tab);
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
	free(p);
	if (i < nchunks) {
		for (--i; i >= 0; --i)
			chfs_async_rpc_inode_read_wait(NULL, &req[i].s, &err,
				&req[i].r);
		free(req);
		if (ret != HG_SUCCESS)
			chfs_set_errno(ret, KV_SUCCESS);
		return (-1);
	}

	ss = 0;
	for (i = 0; i < nchunks; ++i) {
		ret = chfs_async_rpc_inode_read_wait(buf + ss, &req[i].s, &err,
			&req[i].r);
		if (ret != HG_SUCCESS)
			save_ret = ret;
		else if (err != KV_SUCCESS)
			continue;
		ss += req[i].s;
	}
	free(req);
	if (save_ret != HG_SUCCESS) {
		chfs_set_errno(save_ret, KV_SUCCESS);
		return (-1);
	}
	return (ss);
}
#endif

ssize_t
chfs_read(int fd, void *buf, size_t size)
{
	struct fd_table *tab = get_fd_table(fd);
	ssize_t s;

	s = chfs_pread(fd, buf, size, tab->pos);
	if (s > 0)
		tab->pos += s;
	release_fd_table(tab);
	return (s);
}

static int
chfs_unlink_chunk_all(char *path, int index);

#define UNLINK_CHUNK_SIZE	10

int
chfs_unlink(const char *path)
{
	char *p = canonical_path(path);
	int ret, err, i;
	size_t psize;
	void *pi;

	if (p == NULL)
		return (-1);
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
	mode = 0777 | S_IFLNK;
	len = strlen(target);
	/* chunk_size is len but symlink(2) requires the last null byte */
	ret = chfs_rpc_inode_create_data(p, strlen(p) + 1, mode, len, target,
		len + 1, &err);
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
	char *p = canonical_path(path);
	size_t s = size;
	hg_return_t ret;
	int err;

	if (p == NULL)
		return (-1);
	ret = chfs_rpc_inode_read(p, strlen(p) + 1, buf, &s, 0, &err);
	free(p);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		chfs_set_errno(ret, err);
		return (-1);
	}
	return (s);
}

static void
root_stat(struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFDIR | 0755;
}

int
chfs_stat(const char *path, struct stat *st)
{
	char *p = canonical_path(path);
	struct fs_stat sb;
	size_t psize;
	void *pi;
	hg_return_t ret;
	int err, i, j;

	if (p == NULL)
		return (-1);
	if (p[0] == '\0') {
		root_stat(st);
		free(p);
		return (0);
	}
	ret = chfs_rpc_inode_stat(p, strlen(p) + 1, &sb, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS) {
		free(p);
		chfs_set_errno(ret, err);
		return (-1);
	}
	st->st_mode = sb.mode;
	st->st_uid = sb.uid;
	st->st_gid = sb.gid;
	st->st_size = sb.size;
	st->st_mtim = sb.mtime;
	st->st_ctim = sb.ctime;
	st->st_nlink = 1;
	if (!S_ISREG(sb.mode) || sb.size < sb.chunk_size) {
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
	int err, i;

	if (len < 0) {
		errno = EINVAL;
		return (-1);
	}
	p = canonical_path(path);
	if (p == NULL)
		return (-1);
	ret = chfs_rpc_inode_stat(p, strlen(p) + 1, &sb, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS || !S_ISREG(sb.mode)) {
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
	return (time(NULL) - node_list_cache_time >
		chfs_node_list_cache_timeout);
}

static void
chfs_ring_list_copy(node_list_t *node_list)
{
	int i;
	hg_return_t ret;

	ring_list_copy(node_list);
	if (chfs_node_list_cache_is_timeout()) {
		log_debug("chfs_ring_list_copy: node_list cache timeout");
		for (i = 0; i < node_list->n; ++i) {
			if (node_list->s[i].address == NULL)
				continue;
			ret = ring_list_rpc_node_list(node_list->s[i].address);
			if (ret == HG_SUCCESS)
				break;
			log_notice("%s: %s", node_list->s[i].address,
				HG_Error_to_string(ret));
		}
		if (i == node_list->n)
			log_fatal("chfs_ring_list_copy: no server");
		ring_list_copy_free(node_list);
		ring_list_copy(node_list);
		node_list_cache_time = time(NULL);
	}
}

int
chfs_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t))
{
	char *p = canonical_path(path);
	node_list_t node_list;
	hg_return_t ret;
	int err, i;

	if (p == NULL)
		return (-1);
	chfs_ring_list_copy(&node_list);
	for (i = 0; i < node_list.n; ++i) {
		if (node_list.s[i].address == NULL)
			continue;
		ret = fs_rpc_readdir(node_list.s[i].address, p, buf, filler,
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
	int i;

	chfs_ring_list_copy(&node_list);
	for (i = 0; i < node_list.n; ++i) {
		if (node_list.s[i].address == NULL)
			continue;
		ret = fs_async_rpc_inode_unlink_chunk_all(
				node_list.s[i].address, p, index);
		if (ret != HG_SUCCESS)
			continue;
	}
	ring_list_copy_free(&node_list);
	return (0);
}
