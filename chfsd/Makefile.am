sbin_PROGRAMS = chfsd
noinst_HEADERS = ring.h ring_rpc.h fs.h kv.h host.h

chfsd_SOURCES = chfsd.c ring.c ring_rpc.c fs_server.c host.c
if USE_PMEMKV
chfsd_SOURCES += fs_server_kv.c fs_kv.c pmemkv.c
else
chfsd_SOURCES += fs_server_posix.c fs_posix.c
endif

chfsd_LDADD = $(top_builddir)/lib/libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
if USE_PMEMKV
chfsd_LDADD += @LIBPMEMKV_LIBS@
chfsd_CFLAGS = @LIBPMEMKV_CFLAGS@
endif

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread
