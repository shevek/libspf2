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
# include <stdlib.h>       /* malloc / free */
# include <stdarg.h>
# include <stdio.h>
#endif

#include "spf.h"
#include "spf_internal.h"


/*
 * standard expanded error formating routines
 */

void
SPF_errorx( const char *file, int line, const char *format, ... )
{
    char	errmsg[SPF_SYSLOG_SIZE];
    va_list ap;
    
    if (SPF_error_handler == NULL)
		abort();
    
    va_start(ap, format);
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    va_end(ap);

    SPF_error_handler(file, line, errmsg);
    abort();
}


void
SPF_warningx( const char *file, int line, const char *format, ... )
{
    char	errmsg[SPF_SYSLOG_SIZE];
    va_list ap;

    if (SPF_warning_handler == NULL)
		return;

    va_start(ap, format);
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    va_end(ap);

    SPF_warning_handler(file, line, errmsg);
}


void
SPF_infox( const char *file, int line, const char *format, ... )
{
    char	errmsg[SPF_SYSLOG_SIZE];
    va_list ap;

    if (SPF_info_handler == NULL)
		return;

    va_start(ap, format);
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    va_end(ap);

    SPF_info_handler(file, line, errmsg);
}


void
SPF_debugx( const char *file, int line, const char *format, ... )
{
    char	errmsg[SPF_SYSLOG_SIZE];
    va_list ap;

    if (SPF_debug_handler == NULL)
		return;

    va_start(ap, format);
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    va_end(ap);

    SPF_debug_handler(file, line, errmsg);
}



/*
 * error reporting routines that accept a va_list
 */

void
SPF_errorv(const char *file, int line, const char *format, va_list ap)
{
    char	errmsg[SPF_SYSLOG_SIZE];
    
    if (SPF_error_handler == NULL)
		abort();
    
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    SPF_error_handler( file, line, errmsg );

    abort();
}


void
SPF_warningv(const char *file, int line, const char *format, va_list ap)
{
    char	errmsg[SPF_SYSLOG_SIZE];
    
    if (SPF_warning_handler == NULL)
		return;
    
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    SPF_warning_handler(file, line, errmsg);
}


void
SPF_infov(const char *file, int line, const char *format, va_list ap)
{
    char	errmsg[SPF_SYSLOG_SIZE];
    
    if (SPF_info_handler == NULL)
		return;
    
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    SPF_info_handler(file, line, errmsg);
}


void
SPF_debugv(const char *file, int line, const char *format, va_list ap)
{
    char	errmsg[SPF_SYSLOG_SIZE];
    
    if (SPF_debug_handler == NULL)
		return;
    
    vsnprintf(errmsg, sizeof(errmsg), format, ap);
    SPF_debug_handler(file, line, errmsg);
}


/*
 * reporting routines for braindead compilers
 */

void
SPF_errorx2(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    SPF_errorv(NULL, 0, format, ap);
    va_end(ap);
}

void
SPF_warningx2(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    SPF_warningv(NULL, 0, format, ap);
    va_end(ap);
}

void
SPF_infox2(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    SPF_infov(NULL, 0, format, ap);
    va_end(ap);
}

void
SPF_debugx2(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    SPF_debugv(NULL, 0, format, ap);
    va_end(ap);
}
