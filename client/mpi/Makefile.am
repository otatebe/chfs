bin_PROGRAMS = chfind
bin_SCRIPTS = chfindrun

CC=$(MPICC)

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread $(top_builddir)/lib/libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
