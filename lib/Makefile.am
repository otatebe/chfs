lib_LTLIBRARIES = libchfs.la
include_HEADERS = chfs.h
noinst_HEADERS = ring_list.h ring_list_rpc.h ring_types.h \
	kv_types.h kv_err.h fs_rpc.h fs_types.h path.h murmur3.h log.h \
	ll.h hash.h

libchfs_la_SOURCES = chfs.c ring_list.c ring_list_rpc.c \
	kv_err.c fs_client.c path.c murmur3.c log.c \
	ll.c hash.c

AM_CPPFLAGS = -Wall -pthread
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread
