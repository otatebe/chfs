#include <stddef.h>
#include <ctype.h>

void
koyama_hash(const void *buf, size_t size, unsigned int *digest)
{
	const char *b = buf, *be = buf + size;
	unsigned int d = 0, l;

	while (b < be) {
		if (isdigit(*b)) {
			l = 0;
			while (b < be && isdigit(*b))
				l = l * 10 + *b++ - '0';
		} else
			l = *b++;
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
	printf("hash(%s, %ld) = %u\n", (char *)buf, size, d);
}

int
main()
{
	test("a", 1);
	test("abc", 3);
	test("abc12300", 7);
	test("abc1230\0003", 9);
	test("abc12300a10", 10);
	return (0);
}
#endif
