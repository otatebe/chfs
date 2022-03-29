#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([CHFS], [1.0.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([README.md])
AC_CONFIG_HEADERS([lib/config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
LT_INIT

AC_CHECK_PROG([PANDOC], [pandoc], [yes])
AM_CONDITIONAL([HAVE_PANDOC], [test x$PANDOC = xyes])

AC_MSG_CHECKING([whether modular hashing is used])
AC_ARG_ENABLE([modular-hashing],
  [AS_HELP_STRING([--enable-modular-hashing],
    [use modular hashing @<:@default=yes@:>@])],
  [], [enableval=yes])
AC_MSG_RESULT([$enableval])
if test x$enableval != xno; then
  AC_DEFINE([USE_MODULAR_HASHING], [1], [Use modular hashing])
fi

AC_MSG_CHECKING([whether xattr is used for metadata])
AC_ARG_ENABLE([xattr],
  [AS_HELP_STRING([--enable-xattr],
    [use xattr for metadata @<:@default=yes@:>@])],
  [], [enableval=yes])
AC_MSG_RESULT([$enableval])
if test x$enableval != xno; then
  AC_DEFINE([USE_XATTR], [1], [Use xattr for metadata])
fi

AC_MSG_CHECKING([whether port number is included to hash])
AC_ARG_ENABLE([hash-port],
  [AS_HELP_STRING([--enable-hash-port],
    [include port number to hash @<:@default=no@:>@])],
  [], [enableval=no])
AC_MSG_RESULT([$enableval])
if test x$enableval != xno; then
  AC_DEFINE([ENABLE_HASH_PORT], [1], [Include port number to hash])
fi

AC_MSG_CHECKING([whether zero copy read rdma is used])
AC_ARG_ENABLE([zero-copy-read-rdma],
  [AS_HELP_STRING([--enable-zero-copy-read-rdma],
    [use zero copy read rdma @<:@default=no@:>@])],
  [], [enableval=no])
AC_MSG_RESULT([$enableval])
if test x$enableval != xno; then
  AC_DEFINE([USE_ZERO_COPY_READ_RDMA], [1], [Use zero copy read rdma])
fi

# Checks for libraries.
PKG_CHECK_MODULES([MARGO], [margo])
PKG_CHECK_MODULES([FUSE], [fuse])

AC_MSG_CHECKING([whether MD5 digest is used])
AC_ARG_ENABLE([digest-md5],
  [AS_HELP_STRING([--enable-digest-md5],
    [use md5 digest @<:@default=no@:>@])],
  [], [enableval=no])
AC_MSG_RESULT([$enableval])
if test x$enableval != xno; then
  AC_DEFINE([USE_DIGEST_MD5], [1], [Use md5 digest])
  PKG_CHECK_MODULES([OPENSSL], [openssl])
fi

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

AC_MSG_CHECKING([abt-io])
AC_ARG_WITH([abt-io],
  [AS_HELP_STRING([--with-abt-io],
    [use abt-io @<:@default=no@:>@])],
  [], [with_abt_io=no])
AC_MSG_RESULT([$with_abt_io])
AM_CONDITIONAL([USE_ABT_IO], [test x$with_abt_io != xno])
if test x$with_abt_io != xno; then
  AC_DEFINE([USE_ABT_IO], [1], [Use abt-io])
  PKG_CHECK_MODULES([ABT_IO], [abt-io])
  AC_CHECK_FUNCS([abt_io_truncate])
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

AC_CONFIG_FILES([Makefile lib/Makefile chfsd/Makefile client/Makefile client/chfsctl doc/Makefile])
AC_OUTPUT
