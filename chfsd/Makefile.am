if USE_PMEMKV
bin_PROGRAMS = chkvdump
endif
sbin_PROGRAMS = chfsd
noinst_HEADERS = ring.h ring_rpc.h fs.h kv.h host.h file.h fs_kv.h lock.h

chfsd_SOURCES = chfsd.c ring.c ring_rpc.c fs_server.c host.c file.c
if USE_PMEMKV
chfsd_SOURCES += fs_server_kv.c lock.c fs_kv.c pmemkv.c
chkvdump_SOURCES = chkvdump.c lock.c fs_kv.c pmemkv.c
else
chfsd_SOURCES += fs_server_posix.c fs_posix.c
endif

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread @MARGO_RPATH@
LDADD = $(top_builddir)/lib/libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
if USE_PMEMKV
AM_CPPFLAGS += @LIBPMEM_CFLAGS@ @LIBPMEMKV_CFLAGS@
LDADD += @LIBPMEM_LIBS@ @LIBPMEMKV_LIBS@
endif
if USE_ABT_IO
AM_CPPFLAGS += @ABT_IO_CFLAGS@
AM_LDFLAGS += @ABT_IO_RPATH@
LDADD += @ABT_IO_LIBS@
endif
