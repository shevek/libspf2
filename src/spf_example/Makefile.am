# Makefile prototype

AUTOMAKE_OPTIONS = foreign
INCLUDES	= -I$(top_builddir)/src/include -I$(top_srcdir)/src/include

#LIBS = /usr/lib/libresolv.a

bin_PROGRAMS	= spf_example spf_example_static \
		  spf_example_2mx spf_example_2mx_static

spf_example_SOURCES = spf_example.c
spf_example_LDADD	= $(top_builddir)/src/libspf2/libspf2.la

spf_example_static_SOURCES = spf_example.c
spf_example_static_LDADD   = $(top_builddir)/src/libspf2/.libs/libspf2.a
spf_example_static_LDFLAGS = -static

spf_example_2mx_SOURCES = spf_example_2mx.c
spf_example_2mx_LDADD	= $(top_builddir)/src/libspf2/libspf2.la

spf_example_2mx_static_SOURCES = spf_example_2mx.c
spf_example_2mx_static_LDADD   = $(top_builddir)/src/libspf2/.libs/libspf2.a
spf_example_2mx_static_LDFLAGS = -static
