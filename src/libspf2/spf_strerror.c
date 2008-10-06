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

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "spf.h"


const char *
SPF_strerror( SPF_errcode_t spf_c_err )
{
    switch ( spf_c_err )
    {
    case SPF_E_SUCCESS:
	return "No errors";
	break;

    case SPF_E_NO_MEMORY:
	return "Out of memory";
	break;

    case SPF_E_NOT_SPF:
	return "Could not find a valid SPF record";
	break;

    case SPF_E_SYNTAX:
	return "Syntax error";
	break;

    case SPF_E_MOD_W_PREF:
	return "Modifiers can not have prefixes";
	break;

    case SPF_E_INVALID_CHAR:
	return "Invalid character found";
	break;
	    
    case SPF_E_UNKNOWN_MECH:
	return "Unknown mechanism found";
	break;
	    
    case SPF_E_INVALID_OPT:
	return "Invalid option found";
	break;
	    
    case SPF_E_INVALID_CIDR:
	return "Invalid CIDR length";
	break;
	    
    case SPF_E_MISSING_OPT:
	return "Required option is missing";
	break;

    case SPF_E_INTERNAL_ERROR:
	return "Internal programming error";
	break;

    case SPF_E_INVALID_ESC:
	return "Invalid %-escape character";
	break;
	    
    case SPF_E_INVALID_VAR:
	return "Invalid macro variable";
	break;
	    
    case SPF_E_BIG_SUBDOM:
	return "Subdomain truncation depth too large";
	break;
	    
    case SPF_E_INVALID_DELIM:
	return "Invalid delimiter character";
	break;
	    
    case SPF_E_BIG_STRING:
	return "Option string too long";
	break;
	    
    case SPF_E_BIG_MECH:
	return "Too many mechanisms";
	break;
	    
    case SPF_E_BIG_MOD:
	return "Too many modifiers";
	break;
	    
    case SPF_E_BIG_DNS:
	return "Mechanisms used too many DNS lookups";
	break;
	    
    case SPF_E_INVALID_IP4:
	return "Invalid IPv4 address literal";
	break;
	    
    case SPF_E_INVALID_IP6:
	return "Invalid IPv6 address literal";
	break;
	    
    case SPF_E_INVALID_PREFIX:
	return "Invalid mechanism prefix";
	break;
	    
    case SPF_E_RESULT_UNKNOWN:
	return "SPF result is \"unknown\"";
	break;
	    
    case SPF_E_UNINIT_VAR:
	return "Uninitialized variable";
	break;
	    
    case SPF_E_MOD_NOT_FOUND:
	return "Modifier not found";
	break;
	    
    case SPF_E_NOT_CONFIG:
	return "Not configured";
	break;
	    
    case SPF_E_DNS_ERROR:
	return "DNS lookup failure";
	break;
	    
    case SPF_E_BAD_HOST_IP:
	return "Invalid hostname (possibly an IP address?)";
	break;
	    
    case SPF_E_BAD_HOST_TLD:
	return "Hostname has a missing or invalid TLD";
	break;
	    
    case SPF_E_MECH_AFTER_ALL:
	return "Mechanisms found after the \"all:\" mechanism will be ignored";
	break;

	case SPF_E_INCLUDE_RETURNED_NONE:
	return "include: mechanism returned 'none'";
	break;

	case SPF_E_RECURSIVE:
	return "include: or redirect= caused unlimited recursion";
	break;

	case SPF_E_MULTIPLE_RECORDS:
	return "Multiple SPF or TXT records for domain.";
	break;

    default:
	return "Unknown SPF error code";
	break;
    }

    return 0;
}
