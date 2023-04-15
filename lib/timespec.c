#include <time.h>
#include <stdio.h>

int
timespec_str(struct timespec *ts, char *s, size_t size)
{
	struct tm *tm;
	size_t s0, s2;
	int s1;

	tm = localtime(&ts->tv_sec);
	s0 = strftime(s, size, "%Y-%m-%d %H:%M:%S", tm);
	if (s0 == 0)
		return (0);
	s1 = snprintf(s + s0, size - s0, ".%09ld ", ts->tv_nsec);
	if (s1 < 0 || s1 >= size - s0)
		return (s1);
	s2 = strftime(s + s0 + s1, size - s0 - s1, "%z", tm);
	return (s0 + s1 + s2);
}

/* t3 = t2 - t1 */
void
timespec_sub(struct timespec *t1, struct timespec *t2, struct timespec *t3)
{
	int borrow = 0;

	t3->tv_nsec = t2->tv_nsec - t1->tv_nsec;
	if (t3->tv_nsec < 0) {
		t3->tv_nsec += 1000000000;
		++borrow;
	}
	t3->tv_sec = t2->tv_sec - borrow - t1->tv_sec;
}
