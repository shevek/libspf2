/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 * 
 *   a) The GNU Lesser General Public License as published by the Free
 *	  Software Foundation; either version 2.1, or (at your option) any
 *	  later version,
 * 
 *   OR
 * 
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */


#include "spf_sys_config.h"

#ifdef STDC_HEADERS
# include <stdlib.h>	   /* malloc / free */
# include <ctype.h>		/* isupper / tolower */
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif



#include "spf.h"
#include "spf_internal.h"


void
SPF_get_lib_version( int *major, int *minor, int *patch )
{
	*major = SPF_LIB_VERSION_MAJOR;
	*minor = SPF_LIB_VERSION_MINOR;
	*patch = SPF_LIB_VERSION_PATCH;
}



char *
SPF_sanitize( SPF_server_t *spf_server, char *str )
{
	char *p;
	
		SPF_ASSERT_NOTNULL(spf_server);

	if ( !spf_server->sanitize )
		return str;

	if ( str == NULL )
		return str;
	
	for( p = str; *p != '\0'; p++ )
		if ( !isprint( (unsigned char)*p ) )
			*p = '?';

	return str;
}





/* To spf_util.c */
const char *
SPF_strresult( SPF_result_t result )
{
	switch( result )
	{
		case SPF_RESULT_INVALID:
		return "(invalid)";
		break;

	case SPF_RESULT_PASS:				/* +								*/
		return "pass";
		break;

	case SPF_RESULT_FAIL:				/* -								*/
		return "fail";
		break;

	case SPF_RESULT_SOFTFAIL:				/* ~								*/
		return "softfail";
		break;

	case SPF_RESULT_NEUTRAL:				/* ?								*/
		return "neutral";
		break;

	case SPF_RESULT_PERMERROR:				/* permanent error				*/
		return "unknown (permanent error)";
		break;

	case SPF_RESULT_TEMPERROR:				/* temporary error				*/
		return "error (temporary)";
		break;

	case SPF_RESULT_NONE:				/* no SPF record found				*/
		return "none";
		break;

	default:
		return "(error: unknown result)";
		break;
	}
}



/* To spf_util.c */
const char *
SPF_strreason( SPF_reason_t reason )
{
	switch( reason )
	{
	case SPF_REASON_NONE:
		return "none";
		break;
		
	case SPF_REASON_LOCALHOST:
		return "localhost";
		break;
		
	case SPF_REASON_LOCAL_POLICY:
		return "local policy";
		break;
		
	case SPF_REASON_MECH:
		return "mechanism";
		break;
		
	case SPF_REASON_DEFAULT:
		return "default";
		break;
		
	case SPF_REASON_2MX:
		return "secondary MX";
		break;
		
	default:
		return "(invalid reason)";
		break;
		
	}
}
