# Makefile prototype

AUTOMAKE_OPTIONS = foreign
AM_CPPFLAGS	= -I$(top_srcdir)/src/include -I$(top_srcdir)/src

#LIBS = /usr/lib/libresolv.a

bin_PROGRAMS	= spfd spfd_static

spfd_SOURCES = spfd.c
spfd_LDADD	= $(top_builddir)/src/libspf2/libspf2.la

spfd_static_SOURCES = spfd.c
spfd_static_LDADD   = $(top_builddir)/src/libspf2/.libs/libspf2.a
spfd_static_LDFLAGS = -static
