AUTOMAKE_OPTIONS = foreign

EXTRA_DIST		= bootstrap LICENSES INSTALL Changelog README TODO win32

SUBDIRS = src tests docs

dist-hook:
	@for file in $(EXTRA_DIST); do \
		find $(distdir)/$$file -name .svn | xargs rm -rf; \
	done
