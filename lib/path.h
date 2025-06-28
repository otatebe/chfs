void path_set_cwd(char *path, const char *diag);
char *path_get_cwd(void);
char *canonical_path(const char *);
char *canonical_fullpath(const char *);
void path_set_subdir_path(const char *);
void path_set_backend_path(const char *);
char *path_backend(const char *);
