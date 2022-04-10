if HAVE_MPI
bin_PROGRAMS = chfind
endif

CC=$(MPICC)

AM_CPPFLAGS = -Wall -pthread -I$(top_srcdir)/lib
AM_CFLAGS = @MARGO_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = -pthread $(top_builddir)/lib/libchfs.la @MARGO_LIBS@ @OPENSSL_LIBS@
