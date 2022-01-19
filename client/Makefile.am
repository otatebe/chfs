bin_PROGRAMS = chlist chfuse chmkdir chrmdir chstagein murmur3sum
nodist_bin_SCRIPTS = chfsctl

chfuse_LDADD = @FUSE_LIBS@
chfuse_CFLAGS = @FUSE_CFLAGS@

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread $(top_builddir)/lib/libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
