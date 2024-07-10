#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int
key_index(char *key, size_t key_size)
{
	int index = 0, slen = strlen(key) + 1;

	if (slen < key_size)
		index = atoi(key + slen);
	return (index);
}
