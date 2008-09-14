/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 * 
 *   a) The GNU Lesser General Public License as published by the Free
 *      Software Foundation; either version 2.1, or (at your option) any
 *      later version,
 * 
 *   OR
 * 
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */


#include "spf_sys_config.h"


#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>       /* malloc / free */
#endif

#ifdef HAVE_SYSLOG_H

#include <syslog.h>        /* stdin / stdout */

#include "spf.h"

/**
 * @file
 * Audited, 2008-09-13, Shevek.
 * Make sure no file:line combo is >127 bytes long.
 */

void
SPF_error_syslog(const char *file, int line, const char *errmsg)
{
    char	buf[128];
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		syslog(LOG_MAIL | LOG_ERR, "%-20s %s", buf, errmsg);
    }
    else {
		syslog(LOG_MAIL | LOG_ERR, "%s", errmsg);
	}
    abort();
}

void
SPF_warning_syslog(const char *file, int line, const char *errmsg)
{
    char	buf[128];
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		syslog(LOG_MAIL | LOG_WARNING, "%-20s %s", buf, errmsg);
    }
    else {
		syslog(LOG_MAIL | LOG_WARNING, "%s", errmsg);
	}
}

void
SPF_info_syslog(const char *file __attribute__ ((unused)), int line __attribute__ ((unused)), const char *errmsg)
{
    syslog(LOG_MAIL | LOG_INFO, "%s", errmsg);
}

void
SPF_debug_syslog(const char *file, int line, const char *errmsg)
{
    char	buf[128] = "";
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		syslog(LOG_MAIL | LOG_DEBUG, "%-20s %s", buf, errmsg);
    }
    else {
		syslog(LOG_MAIL | LOG_DEBUG, "%s", errmsg);
	}
}

#endif
