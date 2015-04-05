AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST		= bootstrap LICENSES INSTALL README TODO win32 perl

SUBDIRS = src @PERL_SUBDIRS@

dist-hook:
	@for file in $(EXTRA_DIST); do \
		find $(distdir)/$$file -name .svn | xargs rm -rf ; \
	done
	@if [ -f perl/Makefile ] ; then \
		make -C perl clean ; \
	fi
