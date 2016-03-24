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


/**
 * Returns the version numbers of this library.
 */
void
SPF_get_lib_version(int *major, int *minor, int *patch)
{
	*major = SPF_LIB_VERSION_MAJOR;
	*minor = SPF_LIB_VERSION_MINOR;
	*patch = SPF_LIB_VERSION_PATCH;
}



/**
 * Sanitizes a string for printing.
 *
 * This replaces all nonprintable characters in str with a '?'.
 * The source string is modified in-place.
 */
char *
SPF_sanitize(SPF_server_t *spf_server, char *str)
{
	char *p;
	
	SPF_ASSERT_NOTNULL(spf_server);

	if (! spf_server->sanitize)
		return str;

	if (str == NULL)
		return str;
	
	for (p = str; *p != '\0'; p++)
		if (! isprint( (unsigned char)*p ))
			*p = '?';

	return str;
}





/**
 * Converts an SPF result to a short human-readable string.
 */
const char *
SPF_strresult(SPF_result_t result)
{
	switch (result) {
		case SPF_RESULT_INVALID:
			return "(invalid)";
			break;

		case SPF_RESULT_PASS:				/* +							*/
			return "pass";
			break;

		case SPF_RESULT_FAIL:				/* -							*/
			return "fail";
			break;

		case SPF_RESULT_SOFTFAIL:			/* ~							*/
			return "softfail";
			break;

		case SPF_RESULT_NEUTRAL:			/* ?							*/
			return "neutral";
			break;

		case SPF_RESULT_PERMERROR:			/* permanent error				*/
			return "permerror";
			break;

		case SPF_RESULT_TEMPERROR:			/* temporary error				*/
			return "temperror";
			break;

		case SPF_RESULT_NONE:				/* no SPF record found			*/
			return "none";
			break;

		default:
			return "(error: unknown result)";
			break;
	}
}



/**
 * Converts an SPF reason to a short human-readable string.
 */
const char *
SPF_strreason(SPF_reason_t reason)
{
	switch (reason) {
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

const char *
SPF_strrrtype(ns_type rr_type)
{
	switch (rr_type) {
		case ns_t_a:       return "A";
		case ns_t_aaaa:    return "AAAA";
		case ns_t_any:     return "ANY";
		case ns_t_invalid: return "BAD";
		case ns_t_mx:      return "MX";
		case ns_t_ptr:     return "PTR";
		case ns_t_txt:     return "TXT";
		default:           return "??";
	}
}

/**
 * This is NOT a general-purpose realloc. It is used only for
 * text buffers. It will allocate at least 64 bytes of storage.
 *
 * This function is allowed to zero all the RAM returned, so it
 * really isn't a realloc.
 *
 * Do not call this function from outside the library.
 */
SPF_errcode_t
SPF_recalloc(char **bufp, size_t *buflenp, size_t buflen)
{
	char		*buf;

	if (*buflenp < buflen) {
		if (buflen < 64)
			buflen = 64;
		buf = realloc(*bufp, buflen);
		if (buf == NULL)
			return SPF_E_NO_MEMORY;

		// memset(buf + *buflenp, '\0', buflen - *buflenp);	
		*bufp = buf;
		*buflenp = buflen;
	}
	else {
		SPF_ASSERT_NOTNULL(*bufp);
	}

	memset(*bufp, '\0', *buflenp);
	return SPF_E_SUCCESS;
}
