lib_LTLIBRARIES = libchfs.la
include_HEADERS = chfs.h
noinst_HEADERS = chfs_err.h ring_list.h ring_list_rpc.h ring_types.h \
	kv_types.h kv_err.h fs_rpc.h fs_types.h path.h shash.h murmur3.h \
	timespec.h log.h

libchfs_la_SOURCES = chfs.c chfs_err.c ring_list.c ring_list_rpc.c \
	kv_err.c fs_client.c path.c shash.c murmur3.c timespec.c log.c

AM_CPPFLAGS = -Wall -pthread
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread @MARGO_RPATH@
