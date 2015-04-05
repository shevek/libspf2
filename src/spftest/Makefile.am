# Makefile prototype

AUTOMAKE_OPTIONS = foreign
AM_CPPFLAGS	= -I$(top_builddir)/src/include -I$(top_srcdir)/src/include

#LIBS = /usr/lib/libresolv.a

bin_PROGRAMS	= spftest spftest_static

spftest_SOURCES = spftest.c
spftest_LDADD	= $(top_builddir)/src/libspf2/libspf2.la

spftest_static_SOURCES = spftest.c
spftest_static_LDADD   = $(top_builddir)/src/libspf2/.libs/libspf2.a
spftest_static_LDFLAGS = -static
