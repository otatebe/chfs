if HAVE_PANDOC
man1_MANS = chfind.1 chfsctl.1 chlist.1 chmkdir.1 chrmdir.1 chfuse.1
man8_MANS = chfsd.8
endif
EXTRA_DIST = chfind.1.md chfsctl.1.md chlist.1.md chmkdir.1.md chrmdir.1.md \
	chfuse.1.md  chfsd.8.md
CLEANFILES = $(man1_MANS) $(man8_MANS)

SUFFIXES = .1 .8 .1.md .8.md

.1.md.1:
	pandoc -s -t man $< -o $@

.8.md.8:
	pandoc -s -t man $< -o $@
