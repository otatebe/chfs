bin_PROGRAMS = chlist chfuse chmkdir chrmdir
nodist_bin_SCRIPTS = chfsctl
sbin_PROGRAMS = chfsd
lib_LTLIBRARIES = libchfs.la
include_HEADERS = chfs.h
noinst_HEADERS = ring_list.h ring_list_rpc.h ring_types.h ring_rpc.h ring.h \
	kv_types.h kv.h kv_err.h fs_rpc.h fs_types.h fs.h host.h log.h

chlist_LDADD = libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
chmkdir_LDADD = libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
chrmdir_LDADD = libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
chfuse_LDADD = libchfs.la @FUSE_LIBS@ @MARGO_LIBS@ @OPENSSL_LIBS@
chfuse_CFLAGS = @FUSE_CFLAGS@

libchfs_la_SOURCES = chfs.c ring_list.c ring_list_rpc.c log.c kv_err.c fs_client.c

chfsd_SOURCES = chfsd.c ring.c ring_rpc.c fs_server.c host.c
if USE_PMEMKV
chfsd_SOURCES += fs_server_kv.c fs_kv.c pmemkv.c
else
chfsd_SOURCES += fs_server_posix.c fs_posix.c
endif

chfsd_LDADD = libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
if USE_PMEMKV
chfsd_LDADD += @LIBPMEMKV_LIBS@
chfsd_CFLAGS = @LIBPMEMKV_CFLAGS@
endif

AM_CPPFLAGS = -Wall -pthread
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread
ACLOCAL_AMFLAGS = -I m4
