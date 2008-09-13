# Makefile prototype

AUTOMAKE_OPTIONS = foreign
INCLUDES	= -I$(top_srcdir)/src/include -I$(top_srcdir)/src

#LIBS = /usr/lib/libresolv.a

bin_PROGRAMS	= spfquery spfquery_static

spfquery_SOURCES = spfquery.c
spfquery_LDADD	= $(top_builddir)/src/libspf2/libspf2.la

spfquery_static_SOURCES = spfquery.c
spfquery_static_LDADD	= $(top_builddir)/src/libspf2/.libs/libspf2.a
spfquery_static_LDFLAGS = -static
