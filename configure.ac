#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([CHFS], [1.0.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([chfs.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Checks for libraries.
PKG_CHECK_MODULES([MARGO], [margo])
PKG_CHECK_MODULES([OPENSSL], [openssl])
PKG_CHECK_MODULES([FUSE], [fuse])

AC_MSG_CHECKING([pmemkv])
AC_ARG_WITH([pmemkv],
  [AS_HELP_STRING([--with-pmemkv],
    [use pmemkv @<:@default=no@:>@])],
  [], [with_pmemkv=no])
AC_MSG_RESULT([$with_pmemkv])
AM_CONDITIONAL([USE_PMEMKV], [test x$with_pmemkv != xno])
if test x$with_pmemkv != xno; then
  AC_DEFINE([USE_PMEMKV], [1], [Use pmemkv])
  PKG_CHECK_MODULES([LIBPMEMKV], [libpmemkv])
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset mkdir rmdir strchr strdup strerror])

AC_CONFIG_FILES([Makefile chfsctl])
AC_OUTPUT
