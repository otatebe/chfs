#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <margo.h>
#include "ring_types.h"
#include "ring_list.h"
#include "ring_list_rpc.h"
#include "kv_types.h"
#include "kv_err.h"
#include "fs_types.h"
#include "fs_rpc.h"
#include "log.h"
#include "chfs.h"

static char chfs_client[PATH_MAX];
static uint32_t chfs_uid, chfs_gid;
static int chfs_chunk_size = 4096;
static int chfs_get_rdma_thresh = 2048;

static int chfs_fd_table_size;
struct chfs_fd_table {
	char *path;
	mode_t mode;
	int chunk_size, pos;
} *chfs_fd_table;

void
chfs_set_chunk_size(int chunk_size)
{
	log_info("chfs_set_chunk_size: %d", chunk_size);
	chfs_chunk_size = chunk_size;
}

void
chfs_set_get_rdma_thresh(int thresh)
{
	log_info("chfs_set_get_rdma_thresh: %d", thresh);
	chfs_get_rdma_thresh = thresh;
}

static void
init_fd_table()
{
	int i;

	chfs_fd_table_size = 100;
	chfs_fd_table = malloc(sizeof(*chfs_fd_table) * chfs_fd_table_size);
	assert(chfs_fd_table);

	for (i = 0; i < chfs_fd_table_size; ++i)
		chfs_fd_table[i].path = NULL;
}

static char *
margo_protocol(const char *server)
{
	int s = 0;
	char *prot;

	while (server[s] && server[s] != ':')
		++s;
	if (server[s] != ':')
		return (NULL);
	prot = malloc(s + 1);
	assert(prot);
	strncpy(prot, server, s);
	prot[s] = '\0';
	return (prot);
}

int
chfs_init(const char *server)
{
	margo_instance_id mid;
	size_t client_size = sizeof(chfs_client);
	hg_addr_t client_addr;
	char *chunk_size, *rdma_thresh, *prot;
	hg_return_t ret;

	if (server == NULL)
		server = getenv("CHFS_SERVER");
	if (server == NULL)
		log_fatal("chfs_init: no server");
	log_info("chfs_init: server %s", server);

	chunk_size = getenv("CHFS_CHUNK_SIZE");
	if (chunk_size != NULL)
		chfs_set_chunk_size(atoi(chunk_size));

	rdma_thresh = getenv("CHFS_RDMA_THRESH");
	if (rdma_thresh != NULL)
		chfs_set_get_rdma_thresh(atoi(rdma_thresh));

	prot = margo_protocol(server);
	if (prot == NULL)
		log_fatal("chfs_init: no protocol");
	mid = margo_init(prot, MARGO_CLIENT_MODE, 1, 0);
	free(prot);
	ring_list_init(NULL);
	ring_list_rpc_init(mid);
	fs_client_init(mid);

	margo_addr_self(mid, &client_addr);
	margo_addr_to_string(mid, chfs_client, &client_size, client_addr);
	margo_addr_free(mid, client_addr);

	init_fd_table();
	chfs_uid = getuid();
	chfs_gid = getgid();

	ret = ring_list_rpc_node_list(server);
	if (ret != HG_SUCCESS)
		log_fatal("%s: %s", server, HG_Error_to_string(ret));

	return (0);
}

int
chfs_term()
{
	return (0);
}

static int
create_fd(const char *path, mode_t mode, int chunk_size)
{
	struct chfs_fd_table *tmp;
	int fd, i;

	for (fd = 0; fd < chfs_fd_table_size; ++fd)
		if (chfs_fd_table[fd].path == NULL)
			break;
	if (fd == chfs_fd_table_size) {
		tmp = realloc(chfs_fd_table,
			sizeof(*chfs_fd_table) * chfs_fd_table_size * 2);
		if (tmp == NULL)
			return (-1);
		chfs_fd_table = tmp;
		chfs_fd_table_size *= 2;
		for (i = fd; i < chfs_fd_table_size; ++i)
			chfs_fd_table[i].path = NULL;
	}
	chfs_fd_table[fd].path = strdup(path);
	assert(chfs_fd_table[fd].path);
	chfs_fd_table[fd].mode = mode;
	chfs_fd_table[fd].chunk_size = chunk_size;
	chfs_fd_table[fd].pos = 0;
	return (fd);
}

static int
clear_fd(int fd)
{
	if (fd < 0 || fd >= chfs_fd_table_size)
		return (-1);
	if (chfs_fd_table[fd].path == NULL)
		return (-1);
	free(chfs_fd_table[fd].path);
	chfs_fd_table[fd].path = NULL;
	return (0);
}

static struct chfs_fd_table *
get_fd_table(int fd)
{
	if (fd < 0 || fd >= chfs_fd_table_size)
		return (NULL);
	if (chfs_fd_table[fd].path == NULL)
		return (NULL);
	return (&chfs_fd_table[fd]);
}

static hg_return_t
chfs_rpc_inode_create(void *key, size_t key_size, mode_t mode, int chunk_size,
	int *errp)
{
	char *target;
	hg_return_t ret;

	while (1) {
		target = ring_list_lookup(key, key_size);
		ret = fs_rpc_inode_create(target, key, key_size, chfs_uid,
			chfs_gid, mode, chunk_size, errp);
		if (ret == HG_SUCCESS)
			break;
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_rpc_inode_write(void *key, size_t key_size, const void *buf, size_t *size,
	size_t offset, mode_t mode, int chunk_size, int *errp)
{
	char *target;
	hg_return_t ret;

	while (1) {
		target = ring_list_lookup(key, key_size);
		ret = fs_rpc_inode_write(target, key, key_size, buf,
			size, offset, mode, chunk_size, errp);
		if (ret == HG_SUCCESS)
			break;
		ring_list_remove(target);
		free(target);
	}
	free(target);
	return (ret);
}

static hg_return_t
chfs_rpc_inode_read(void *key, size_t key_size, void *buf, size_t *size,
	size_t offset, int *errp)
{
	char *target;
	hg_return_t ret;

	while (1) {
		target = ring_list_lookup(key, key_size);
		if (*size < chfs_get_rdma_thresh)
			ret = fs_rpc_inode_read(target, key, key_size, buf,
				size, offset, errp);
		else
			ret = fs_rpc_inode_read_rdma(target, key, key_size,
				chfs_client, buf, size, offset, errp);
		if (ret == HG_SUCCESS)
			break;
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

	while (1) {
		target = ring_list_lookup(key, key_size);
		ret = fs_rpc_inode_remove(target, key, key_size, errp);
		if (ret == HG_SUCCESS)
			break;
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

	while (1) {
		target = ring_list_lookup(key, key_size);
		ret = fs_rpc_inode_stat(target, key, key_size, st, errp);
		if (ret == HG_SUCCESS)
			break;
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
	hg_return_t ret;
	int fd, err;

	mode |= S_IFREG;
	fd = create_fd(path, mode, chunk_size);
	if (fd < 0)
		return (-1);

	ret = chfs_rpc_inode_create((void *)path, strlen(path) + 1,
		mode, chunk_size, &err);
	if (ret == HG_SUCCESS && err == KV_SUCCESS)
		return (fd);

	clear_fd(fd);
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
	struct fs_stat st;
	hg_return_t ret;
	int fd, err;

	ret = chfs_rpc_inode_stat((void *)path, strlen(path) + 1, &st, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);

	fd = create_fd(path, st.mode, st.chunk_size);
	if (fd >= 0)
		return (fd);
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
	if (path_index == NULL)
		return (NULL);
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

ssize_t
chfs_pwrite(int fd, const void *buf, size_t size, off_t offset)
{
	struct chfs_fd_table *tab = get_fd_table(fd);
	void *path;
	int index, local_pos, err;
	size_t s = size, ss = 0, psize;
	hg_return_t ret;

	if (tab == NULL)
		return (-1);

	index = offset / tab->chunk_size;
	local_pos = offset % tab->chunk_size;

	if (local_pos + s > tab->chunk_size)
		s = tab->chunk_size - local_pos;
	assert(s > 0);

	path = path_index(tab->path, index, &psize);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_write(path, psize, (void *)buf, &s, local_pos,
		tab->mode, tab->chunk_size, &err);
	free(path);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);

	if (size - s > 0) {
		ss = chfs_pwrite(fd, buf + s, size - s, offset + s);
		if (ss < 0)
			ss = 0;
	}
	return (s + ss);
}

ssize_t
chfs_write(int fd, const void *buf, size_t size)
{
	struct chfs_fd_table *tab = get_fd_table(fd);
	ssize_t s;

	s = chfs_pwrite(fd, buf, size, tab->pos);
	if (s > 0)
		tab->pos += s;
	return (s);
}

ssize_t
chfs_pread(int fd, void *buf, size_t size, off_t offset)
{
	struct chfs_fd_table *tab = get_fd_table(fd);
	void *path;
	int index, local_pos, ret, err;
	size_t s = size, ss = 0, psize;

	if (tab == NULL)
		return (-1);

	index = offset / tab->chunk_size;
	local_pos = offset % tab->chunk_size;

	path = path_index(tab->path, index, &psize);
	if (path == NULL)
		return (-1);
	ret = chfs_rpc_inode_read(path, psize, buf, &s, local_pos, &err);
	free(path);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);
	if (s <= 0)
		return (0);

	if (local_pos + s < tab->chunk_size)
		return (s);
	if (size - s > 0) {
		ss = chfs_pread(fd, buf + s, size - s, offset + s);
		if (ss < 0)
			ss = 0;
	}
	return (s + ss);
}

ssize_t
chfs_read(int fd, void *buf, size_t size)
{
	struct chfs_fd_table *tab = get_fd_table(fd);
	ssize_t s;

	s = chfs_pread(fd, buf, size, tab->pos);
	if (s > 0)
		tab->pos += s;
	return (s);
}

int
chfs_unlink(const char *path)
{
	int ret, err, i;
	size_t psize;
	void *pi;

	ret = chfs_rpc_remove((void *)path, strlen(path) + 1, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);

	for (i = 1; ; ++i) {
		pi = path_index(path, i, &psize);
		if (pi == NULL)
			break;
		ret = chfs_rpc_remove(pi, psize, &err);
		free(pi);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			break;
	}
	return (0);
}

int
chfs_mkdir(const char *path, mode_t mode)
{
	hg_return_t ret;
	int err;

	mode |= S_IFDIR;
	ret = chfs_rpc_inode_create((void *)path, strlen(path) + 1,
		mode, 0, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);
	return (0);
}

int
chfs_rmdir(const char *path)
{
	hg_return_t ret;
	int err;

	/* XXX check child entries */
	ret = chfs_rpc_remove((void *)path, strlen(path) + 1, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);
	return (0);
}

static void
root_stat(struct stat *st)
{
	st->st_mode = S_IFDIR | 0755;
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_size = 0;
}

int
chfs_stat(const char *path, struct stat *st)
{
	struct fs_stat sb;
	size_t psize;
	void *pi;
	hg_return_t ret;
	int err, i;

	if (path[0] == '\0' || strcmp(path, "/") == 0) {
		root_stat(st);
		return (0);
	}
	ret = chfs_rpc_inode_stat((void *)path, strlen(path) + 1, &sb, &err);
	if (ret != HG_SUCCESS || err != KV_SUCCESS)
		return (-1);
	st->st_mode = sb.mode;
	st->st_uid = sb.uid;
	st->st_gid = sb.gid;
	st->st_size = sb.size;
	st->st_nlink = 1;
	if (S_ISDIR(sb.mode) || sb.size < sb.chunk_size)
		return (0);

	for (i = 1; ; ++i) {
		pi = path_index(path, i, &psize);
		if (pi == NULL)
			break;
		ret = chfs_rpc_inode_stat(pi, psize, &sb, &err);
		free(pi);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			break;
		st->st_size += sb.size;
		if (sb.size == 0 || sb.size < sb.chunk_size)
			break;
	}
	return (0);
}

int
chfs_readdir(const char *path, void *buf,
	int (*filler)(void *, const char *, const struct stat *, off_t))
{
	string_list_t node_list;
	hg_return_t ret;
	int err, i;

	ring_list_copy(&node_list);
	for (i = 0; i < node_list.n; ++i) {
		ret = fs_rpc_readdir(node_list.s[i], path, buf, filler, &err);
		if (ret != HG_SUCCESS || err != KV_SUCCESS)
			continue;
	}
	ring_list_copy_free(&node_list);
	return (0);
}
