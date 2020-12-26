void ring_init(const char *, const char *);

void ring_set_next(const char *);
void ring_set_next_next(const char *);
void ring_set_prev(const char *);
void ring_set_prev_prev(const char *);

char *ring_get_self_name();
char *ring_get_self();

char *ring_get_next();
char *ring_get_next_next();
char *ring_get_prev();
char *ring_get_prev_prev();

void ring_release_next();
void ring_release_next_next();
void ring_release_prev();
void ring_release_prev_prev();
