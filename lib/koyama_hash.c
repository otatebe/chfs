#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
	
void
koyama_hash(const void *buf, size_t size, unsigned int *digest)
{
	const char *b = buf, *be = buf + size;
	char *bt;
	unsigned long d = 0, l;

	while (b < be) {
		if (isdigit(b[0])) {
			l = strtol(b, &bt, 10);
			b = bt;
		} else {
			l = b[0];
			++b;
		}
		d += l;
	}
	*digest = d;
}

#if 0
#include <stdio.h>

void
test(const void *buf, size_t size)
{
	unsigned int d;
	koyama_hash(buf, size, &d);
	printf("hash(%s) = %u\n", (char *)buf, d);
}

int
main()
{
	test("a", 1);
	test("abc", 3);
	test("abc12300", 8);
	test("abc12300a", 9);
	test("abc12300a10", 11);
	return (0);
}
#endif
