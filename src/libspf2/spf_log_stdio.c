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
# include <stdio.h>        /* stdin / stdout */
# include <stdlib.h>       /* malloc / free */
#endif

#include "spf.h"

/**
 * @file
 * Audited, 2008-09-13, Shevek.
 * Make sure no file:line combo is >127 bytes long.
 */

void
SPF_error_stdio(const char *file, int line, const char *errmsg)
{
    char	buf[128];
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		fprintf(stderr, "%-20s Error: %s\n", buf, errmsg);
    }
    else {
		fprintf(stderr, "Error: %s\n", errmsg);
	}
    abort();
}

void
SPF_warning_stdio(const char *file, int line, const char *errmsg)
{
    char	buf[128];
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		fprintf(stderr, "%-20s Warning: %s\n", buf, errmsg);
    }
    else {
		fprintf(stderr, "Warning: %s\n", errmsg);
	}
}

void
SPF_info_stdio(const char *file __attribute__((unused)), int line __attribute__((unused)), const char *errmsg)
{
    printf("%s\n", errmsg);
}

void
SPF_debug_stdio(const char *file, int line, const char *errmsg)
{
    char	buf[128];
    if (file) {
		snprintf(buf, sizeof(buf), "%s:%d", file, line);
		fprintf(stderr, "%-20s Debug: %s\n", buf, errmsg);
    }
    else {
		fprintf(stderr, "Debug: %s\n", errmsg);
	}
}
