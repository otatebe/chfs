struct node_list;

void ring_list_init(char *self, char *name);
void ring_list_term(void);
void ring_list_display(int n);
void ring_list_csv(int n);
void ring_list_copy(struct node_list *list);
void ring_list_copy_free(struct node_list *list);
void ring_list_update(struct node_list *src);
void ring_list_remove(char *host);
int ring_list_is_in_charge(const char *key, int key_size);
char *ring_list_lookup_index(int index);
char *ring_list_lookup(const char *key, int key_size);
int ring_list_is_coordinator(char *self);
