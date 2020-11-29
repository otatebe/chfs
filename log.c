#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include "log.h"

static FILE *log_file = NULL;
static int priority_max_level = LOG_INFO;

void
log_set_priority_max_level(int priority)
{
	priority_max_level = priority;
}

static void
log_msg_syslog(int priority, const char *buffer)
{
	syslog(priority, "%s", buffer);
}

static void
log_msg_stderr(int priority, const char *buffer)
{
	fprintf(stderr, "<%d> %s\n", priority, buffer);
}

static void
log_msg_file(int priority, const char *buffer)
{
	fprintf(log_file, "<%d> %s\n", priority, buffer);
}

static void
(*log_msg)(int priority, const char *buffer)
	= log_msg_stderr;

static void
log_vmessage(int priority, const char *format, va_list ap)
{
	char buffer[2048];

	if (priority > priority_max_level)
		return;
	vsnprintf(buffer, sizeof buffer, format, ap);
	log_msg(priority, buffer);
}

void
log_message(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(priority, format, ap);
	va_end(ap);
}

void
log_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_ERR, format, ap);
	va_end(ap);
}

void
log_warning(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_WARNING, format, ap);
	va_end(ap);
}

void
log_notice(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_NOTICE, format, ap);
	va_end(ap);
}

void
log_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_INFO, format, ap);
	va_end(ap);
}

void
log_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_DEBUG, format, ap);
	va_end(ap);
}

void
log_fatal(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_ERR, format, ap);
	va_end(ap);
	exit(2);
}

void
log_syslog_open(const char *log_identifier, int option, int facility)
{
	openlog(log_identifier, option, facility);
	log_msg = log_msg_syslog;
}

void
log_file_open(const char *path)
{
	FILE *f;

	f = fopen(path, "a");
	if (f == NULL)
		return;
	if (log_file != NULL)
		fclose(log_file);
	setbuf(f, NULL);
	log_file = f;
	log_msg = log_msg_file;
}

void
log_term()
{
	if (log_file)
		fclose(log_file);
	log_file = NULL;
	log_msg = log_msg_stderr;
}

