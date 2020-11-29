#ifdef __GNUC__
#define LOG_PRINTF_ARG(M, N) __attribute__((__format__(__printf__, M, N)))
#else
#define LOG_PRINTF_ARG(M, N)
#endif

void log_message(int, const char *, ...) LOG_PRINTF_ARG(2, 3);
void log_error(const char *, ...) LOG_PRINTF_ARG(1, 2);
void log_warning(const char *, ...) LOG_PRINTF_ARG(1, 2);
void log_notice(const char *, ...) LOG_PRINTF_ARG(1, 2);
void log_info(const char *, ...) LOG_PRINTF_ARG(1, 2);
void log_debug(const char *, ...) LOG_PRINTF_ARG(1, 2);

void log_fatal(const char *, ...) LOG_PRINTF_ARG(1, 2);

void log_syslog_open(const char *, int, int);
void log_file_open(const char *);
void log_term();
void log_set_priority_max_level(int);
