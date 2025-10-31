int fs_mkdir_p(char *path, mode_t mode, int (*func)(const char *));
char *fs_dirname(const char *path);
void fs_mkdir_parent(const char *path, int (*func)(const char *));
