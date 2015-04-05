# Makefile prototype

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/src

lib_LTLIBRARIES	= libspf2.la

libspf2_la_SOURCES	= \
	spf_compile.c \
	spf_dns.c \
	spf_dns_cache.c \
	spf_dns_null.c \
	spf_dns_resolv.c \
	spf_dns_rr.c \
	spf_dns_test.c \
	spf_dns_windns.c \
	spf_dns_zone.c \
	spf_expand.c \
	spf_get_exp.c \
	spf_get_spf.c \
	spf_id2str.c \
	spf_interpret.c \
	spf_log.c \
	spf_log_default.c \
	spf_log_stdio.c \
	spf_log_syslog.c \
	spf_print.c \
	spf_record.c \
	spf_request.c \
	spf_response.c \
	spf_server.c \
	spf_strerror.c \
	spf_utils.c \
	spf_win32.c

libspf2_la_LIBADD	= $(top_builddir)/src/libreplace/libreplace.la



libspf2_la_LDFLAGS	= -version-info 3:0:1

# Copied from the libtool info file:
#
#    This flag accepts an argument of the form
# `CURRENT[:REVISION[:AGE]]'.  So, passing `-version-info 3:12:1' sets
# CURRENT to 3, REVISION to 12, and AGE to 1.
# 
#    If either REVISION or AGE are omitted, they default to 0.  Also note
# that AGE must be less than or equal to the CURRENT interface number.
# 
#    Here are a set of rules to help you update your library version
# information:
# 
#   1. Start with version information of `0:0:0' for each libtool library.
# 
#   2. Update the version information only immediately before a public
#      release of your software.  More frequent updates are unnecessary,
#      and only guarantee that the current interface number gets larger
#      faster.
# 
#   3. If the library source code has changed at all since the last
#      update, then increment REVISION (`C:R:A' becomes `C:r+1:A').
# 
#   4. If any interfaces have been added, removed, or changed since the
#      last update, increment CURRENT, and set REVISION to 0.
# 
#   5. If any interfaces have been added since the last public release,
#      then increment AGE.
# 
#   6. If any interfaces have been removed since the last public release,
#      then set AGE to 0.
# 
#    *_Never_* try to set the interface numbers so that they correspond
# to the release number of your package.  This is an abuse that only
# fosters misunderstanding of the purpose of library versions.  Instead,
# use the `-release' flag (*note Release numbers::), but be warned that
# every release of your package will not be binary compatible with any
# other release.
# 
