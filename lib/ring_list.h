struct node_list;

void ring_list_init(char *self);
void ring_list_display();
void ring_list_copy(struct node_list *list);
void ring_list_copy_free(struct node_list *list);
void ring_list_update(struct node_list *src, int flag);
void ring_list_remove(char *host);
int ring_list_is_in_charge(const char *key, int key_size);
char *ring_list_lookup(const char *key, int key_size);
int ring_list_is_coordinator(char *self);
