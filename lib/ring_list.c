#include <stdlib.h>
#include <margo.h>
#include "config.h"
#include "ring_types.h"
#include "ring_list.h"
#include "log.h"

#ifdef USE_DIGEST_MD5
#include <openssl/evp.h>
#include <openssl/md5.h>

static void calc_md5(const uint8_t *buf, uint8_t size, uint8_t *digest)
{
	EVP_MD_CTX *ctx;
	unsigned int len = MD5_DIGEST_LENGTH;

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, buf, size);
	EVP_DigestFinal_ex(ctx, digest, &len);
	EVP_MD_CTX_free(ctx);
}

typedef union {
	uint8_t c[MD5_DIGEST_LENGTH];
#ifdef USE_MODULAR_HASHING
	unsigned __int128 l;
#endif
} HASH_T;
#define HASH(data, len, hash) calc_md5(data, len, hash.c)
#define HASH_CMP(a, b) memcmp(a.c, b.c, MD5_DIGEST_LENGTH)
#ifdef USE_MODULAR_HASHING
#define HASH_MODULO(a, b) (a.l % (b))	/* XXX - ignore endian */
#endif

void display_hash(HASH_T hash)
{
	int i;

	for (i = 0; i < MD5_DIGEST_LENGTH; ++i)
		printf("%02X", hash.c[i]);
}
#else
#include "murmur3.h"

typedef uint32_t HASH_T[1];
#define HASH(data, len, hash) MurmurHash3_x86_32(data, len, 1234, hash)
#define HASH_CMP(a, b) ((a[0] < b[0]) ? -1 : ((a[0] > b[0]) ? 1 : 0))
#ifdef USE_MODULAR_HASHING
#define HASH_MODULO(a, b) (a[0] % (b))
#endif
#define display_hash(hash) printf("%08X", hash[0])
#endif

struct ring_node {
	char *address;
	char *name;
	HASH_T hash;
};

static struct ring_list {
	int n;
	struct ring_node *nodes;
} ring_list;

static char *ring_list_self = NULL;
static int ring_list_self_index = -1;
static ABT_mutex ring_list_mutex;
static char *ring_list_client = NULL;
static char *ring_list_local_server = NULL;

void
ring_list_init(char *self, char *name)
{
	node_list_t n;
	static const char diag[] = "ring_list_init";

	ABT_mutex_create(&ring_list_mutex);
	if (self == NULL) {
		ring_list.n = 0;
		ring_list.nodes = NULL;
		return;
	}
	n.n = 1;
	n.s = malloc(sizeof(n.s[0]));
	if (n.s == NULL)
		log_fatal("%s: no memory", diag);
	n.s[0].address = self;
	n.s[0].name = name;
	ring_list_update(&n);
	free(n.s);

	ring_list_self = strdup(self);
	if (ring_list_self == NULL)
		log_fatal("%s: no memory", diag);
	ring_list_self_index = 0;
}

static void
ring_list_display_node(struct ring_node *node)
{
	printf("%s %s ", node->address, node->name);
	display_hash(node->hash);
	printf("\n");
}

void
ring_list_set_client(char *client)
{
	if (client) {
		free(ring_list_client);
		ring_list_client = strdup(client);
	}
}

void
ring_list_display(int n)
{
	int i;

	ABT_mutex_lock(ring_list_mutex);
	if (n <= 0 || n > ring_list.n)
		n = ring_list.n;
	for (i = 0; i < n; ++i)
		ring_list_display_node(&ring_list.nodes[i]);
	ABT_mutex_unlock(ring_list_mutex);
}

void
ring_list_csv(int n)
{
	int i;

	ABT_mutex_lock(ring_list_mutex);
	if (n <= 0 || n > ring_list.n)
		n = ring_list.n;
	for (i = 0; i < n - 1; ++i)
		printf("%s,", ring_list.nodes[i].address);
	if (i < n)
		printf("%s\n", ring_list.nodes[i].address);
	ABT_mutex_unlock(ring_list_mutex);
}

static void
ring_list_clear()
{
	int i;

	for (i = 0; i < ring_list.n; ++i) {
		free(ring_list.nodes[i].address);
		free(ring_list.nodes[i].name);
	}
	free(ring_list.nodes);
}

void
ring_list_term()
{
	ring_list_clear();
	ring_list.n = 0;
	ring_list.nodes = NULL;
	free(ring_list_self);
	ring_list_self = NULL;
	ring_list_self_index = -1;
	free(ring_list_client);
	ring_list_client = NULL;
	free(ring_list_local_server);
	ring_list_local_server = NULL;

	ABT_mutex_free(&ring_list_mutex);
}

int
ring_list_cmp(const void *a1, const void *a2)
{
	const struct ring_node *n1 = a1, *n2 = a2;

	return (HASH_CMP(n1->hash, n2->hash));
}

void
ring_list_copy(node_list_t *list)
{
	int i;

	ABT_mutex_lock(ring_list_mutex);
	list->n = ring_list.n;
	list->s = malloc(sizeof(list->s[0]) * ring_list.n);
	if (list->s == NULL) {
		log_error("ring_list_copy: no memory");
		list->n = 0;
	}
	for (i = 0; i < list->n; ++i) {
		list->s[i].address = strdup(ring_list.nodes[i].address);
		list->s[i].name = strdup(ring_list.nodes[i].name);
		if (list->s[i].address == NULL || list->s[i].name == NULL)
			log_error("ring_list_copy: no memory");
	}
	ABT_mutex_unlock(ring_list_mutex);
}

void
ring_list_copy_free(node_list_t *list)
{
	int i;

	for (i = 0; i < list->n; ++i) {
		free(list->s[i].address);
		free(list->s[i].name);
	}
	free(list->s);
}

static void
strdiff(const char *s1, const char *s2, int *len, int *diff)
{
	int i = 0;

	if (s1 == NULL || s2 == NULL)
		return;

	while (s1[i] && s1[i] == s2[i])
		++i;
	if (len)
		*len = i;
	if (diff)
		*diff = s1[i] > s2[i] ? s1[i] - s2[i] : s2[i] - s1[i];
	return;
}

static char *
get_local_server_unlocked()
{
	int max_len = 0, min_i = 0, max_num = 0, *c;
	int len = max_len, i;

	if (ring_list_client == NULL || ring_list.n == 0)
		return (NULL);

	c = malloc(sizeof(int) * ring_list.n);
	if (c == NULL)
		return (NULL);

	for (i = 0; i < ring_list.n; ++i) {
		strdiff(ring_list_client, ring_list.nodes[i].address,
			&len, NULL);
		if (max_len < len) {
			max_num = 1;
			c[max_num - 1] = i;
			min_i = i;
			max_len = len;
		} else if (max_len == len) {
			++max_num;
			c[max_num - 1] = i;
			min_i = i;
		}
	}
	/* there are several local candidates, choose randomly */
	if (max_num > 1)
		min_i = c[random() % max_num];
	free(c);
	return (strdup(ring_list.nodes[min_i].address));
}

void
ring_list_update(node_list_t *src)
{
	int i;

	ABT_mutex_lock(ring_list_mutex);
	ring_list_clear();
	ring_list.n = src->n;
	ring_list.nodes = malloc(sizeof(ring_list.nodes[0]) * src->n);
	if (ring_list.nodes == NULL) {
		log_error("ring_list_update: no memory");
		ring_list.n = 0;
		ring_list_self_index = -1;
		goto unlock;
	}
	for (i = 0; i < src->n; ++i) {
		ring_list.nodes[i].address = strdup(src->s[i].address);
		ring_list.nodes[i].name = strdup(src->s[i].name);
		if (ring_list.nodes[i].address == NULL ||
			ring_list.nodes[i].name == NULL)
			log_fatal("ring_list_update: no memory");
		HASH((unsigned char *)ring_list.nodes[i].name,
			strlen(ring_list.nodes[i].name),
			ring_list.nodes[i].hash);
	}
	qsort(ring_list.nodes, ring_list.n, sizeof(ring_list.nodes[0]),
		ring_list_cmp);
	if (ring_list_client) {
		free(ring_list_local_server);
		ring_list_local_server = get_local_server_unlocked();
		log_debug("client: %s local_server: %s", ring_list_client,
			ring_list_local_server);
	}
	if (ring_list_self == NULL)
		goto unlock;
	for (i = 0; i < src->n; ++i)
		if (strcmp(ring_list.nodes[i].address, ring_list_self) == 0)
			break;
	if (i < src->n)
		ring_list_self_index = i;
	else {
		log_notice("ring_list_update: no self server");
		ring_list_self_index = -1;
	}
unlock:
	ABT_mutex_unlock(ring_list_mutex);
}

static char *
ring_list_get_local_server()
{
	if (ring_list_local_server == NULL)
		return (NULL);
	return (strdup(ring_list_local_server));
}

void
ring_list_remove(char *host)
{
	int i;

	if (host == NULL)
		return;
	ABT_mutex_lock(ring_list_mutex);
	for (i = 0; i < ring_list.n; ++i)
		if (strcmp(host, ring_list.nodes[i].address) == 0)
			break;
	if (i < ring_list.n) {
		free(ring_list.nodes[i].address);
		free(ring_list.nodes[i].name);
		--ring_list.n;
		for (; i < ring_list.n; ++i)
			ring_list.nodes[i] = ring_list.nodes[i + 1];
		if (ring_list_client &&
			strcmp(host, ring_list_local_server) == 0) {
			free(ring_list_local_server);
			ring_list_local_server = get_local_server_unlocked();
			log_debug("client: %s local_server: %s",
				ring_list_client, ring_list_local_server);
		}
	}
	if (ring_list.n == 0) {
		log_warning("ring_list_remove: no server");
		free(ring_list.nodes);
		ring_list.nodes = NULL;
	}
	ABT_mutex_unlock(ring_list_mutex);
}

char *
ring_list_lookup_index(int i)
{
	char *r = NULL;

	if (i < 0)
		return (r);
	ABT_mutex_lock(ring_list_mutex);
	if (i < ring_list.n)
		r = strdup(ring_list.nodes[i].address);
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

#ifdef USE_MODULAR_HASHING

int
ring_list_is_in_charge(const char *key, int key_size)
{
	HASH_T hash;
	unsigned int i, index = 0;
	int klen = strlen(key) + 1, r;

	if (klen < key_size)
		index = atoi(key + klen);
	HASH((const unsigned char *)key, klen, hash);
	ABT_mutex_lock(ring_list_mutex);
	i = HASH_MODULO(hash, ring_list.n);
	if (index > 0)
		i = (i + index) % ring_list.n;
	r = i == ring_list_self_index;
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

static char *
ring_list_lookup_modulo(const char *key, int key_size)
{
	HASH_T hash;
	unsigned int i, index = 0;
	int klen = strlen(key) + 1;
	char *r;

	if (klen < key_size)
		index = atoi(key + klen);
	HASH((const unsigned char *)key, klen, hash);
	ABT_mutex_lock(ring_list_mutex);
	i = HASH_MODULO(hash, ring_list.n);
	if (index > 0)
		i = (i + index) % ring_list.n;
	r = strdup(ring_list.nodes[i].address);
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

#else

int
ring_list_is_in_charge(const char *key, int key_size)
{
	HASH_T hash;
	int r = 1;

	HASH((const unsigned char *)key, key_size, hash);
	ABT_mutex_lock(ring_list_mutex);
	if (ring_list_self_index > 0)
		r = (HASH_CMP(ring_list.nodes[ring_list_self_index - 1].hash,
				hash) < 0 && HASH_CMP(hash,
				ring_list.nodes[ring_list_self_index].hash)
					<= 0);
	else if (ring_list_self_index == 0)
		r = (HASH_CMP(ring_list.nodes[ring_list.n - 1].hash, hash)
			< 0 || HASH_CMP(hash, ring_list.nodes[0].hash) <= 0);
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

static char *
ring_list_lookup_linear(const char *key, int key_size)
{
	HASH_T hash;
	char *r;
	int i;

	HASH((const unsigned char *)key, key_size, hash);
	ABT_mutex_lock(ring_list_mutex);
	for (i = 0; i < ring_list.n; ++i)
		if (HASH_CMP(ring_list.nodes[i].hash, hash) >= 0)
			break;
	if (i == ring_list.n)
		i = 0;
	r = strdup(ring_list.nodes[i].address);
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

static char *
ring_list_lookup_internal(HASH_T hash, int low, int hi)
{
	int mid = (low + hi) / 2;

	if (hi - low == 1)
		return (strdup(ring_list.nodes[hi].address));
	if (HASH_CMP(ring_list.nodes[mid].hash, hash) < 0)
		return (ring_list_lookup_internal(hash, mid, hi));
	else
		return (ring_list_lookup_internal(hash, low, mid));
}

static char *
ring_list_lookup_binary(const char *key, int key_size)
{
	HASH_T hash;
	char *r;

	HASH((const unsigned char *)key, key_size, hash);
	ABT_mutex_lock(ring_list_mutex);
	if (HASH_CMP(ring_list.nodes[0].hash, hash) >= 0 ||
		HASH_CMP(ring_list.nodes[ring_list.n - 1].hash, hash) < 0) {
		r = strdup(ring_list.nodes[0].address);
	} else
		r = ring_list_lookup_internal(hash, 0, ring_list.n - 1);
	ABT_mutex_unlock(ring_list_mutex);
	return (r);
}

#endif

static int ring_list_lookup_local = 0;

void
ring_list_set_lookup_local(int enable)
{
	log_info("ring_list_set_lookup_local: %d", enable);
	ring_list_lookup_local = enable;
}

int
ring_list_does_lookup_local()
{
	return (ring_list_lookup_local);
}

char *
ring_list_lookup(const char *key, int key_size)
{
	if (ring_list.n == 0)
		return (NULL);
	if (ring_list_lookup_local)
		return (ring_list_get_local_server());
#ifdef USE_MODULAR_HASHING
	return (ring_list_lookup_modulo(key, key_size));
#else
	if (ring_list.n < 7)
		return (ring_list_lookup_linear(key, key_size));
	else
		return (ring_list_lookup_binary(key, key_size));
#endif
}

int
ring_list_is_coordinator(char *self)
{
	int i, ret = 0;

	ABT_mutex_lock(ring_list_mutex);
	for (i = 0; i < ring_list.n; ++i)
		if (strcmp(self, ring_list.nodes[i].address) < 0)
			break;
	if (i == ring_list.n)
		ret = 1;
	ABT_mutex_unlock(ring_list_mutex);
	return (ret);
}
