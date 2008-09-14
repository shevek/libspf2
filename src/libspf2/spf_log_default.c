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

#include "spf.h"
#include "spf_internal.h"


/**
 * @file
 * Audited, 2008-09-13, Shevek.
 * TODO: Move into spf_log.c ?
 */

void (*SPF_error_handler)( const char *, int, const char * ) __attribute__ ((noreturn)) = SPF_DEFAULT_ERROR_HANDLER;
void (*SPF_warning_handler)( const char *, int, const char * ) = SPF_DEFAULT_WARNING_HANDLER;
void (*SPF_info_handler)( const char *, int, const char * ) = SPF_DEFAULT_INFO_HANDLER;
void (*SPF_debug_handler)( const char *, int, const char * ) = SPF_DEFAULT_DEBUG_HANDLER;
