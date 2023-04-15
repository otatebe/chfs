int timespec_str(struct timespec *ts, char *s, size_t size);

/* t3 = t2 - t1 */
void timespec_sub(struct timespec *t1, struct timespec *t2,
	struct timespec *t3);
