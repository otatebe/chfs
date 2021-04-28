#include <stdio.h>
#include <syslog.h>
#include "kv_err.h"
#include "kv.h"
#include "log.h"

static int
get_all_cb(const char *k, size_t ks, const char *v, size_t vs, void *a)
{
        int i;

        printf("key = ");
        for (i = 0; i < ks; ++i)
                printf("%c", k[i] == '\0' ? '_' : k[i]);
        printf(" size = %ld, value size = %ld\n", ks, vs);

        return (0);
}

int
main(int argc, char *argv[])
{
	int err;

	log_set_priority_max_level(LOG_DEBUG);
	while (*++argv) {
		printf("%s\n", *argv);
		kv_init(*argv, "cmap", "kv.db", 256 * 1024 * 1024);
		err = kv_get_all_cb(get_all_cb, NULL);
		if (err != KV_SUCCESS)
			log_error("%s", kv_err_string(err));
		kv_term();
	}
	return (0);
}

