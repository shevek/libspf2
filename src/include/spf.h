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

#ifndef __GNUC__
#define __attribute__(x)
#endif


#ifndef INC_SPF
#define INC_SPF


#include "spf_lib_version.h"

#include "spf_server.h"
#include "spf_request.h"
#include "spf_response.h"
#include "spf_dns.h"
#include "spf_log.h"


#define SPF_VERSION 1
#define SPF_VER_STR "v=spf1"


/* ********************************************************************* */


/* FYI only -- can't be changed without recompiling the library
 * Most error messages are under 80 characters and we don't want
 * bad/malicious input to cause huge error messages */
#define SPF_C_ERR_MSG_SIZE		(2*80)
#define SPF_SMTP_COMMENT_SIZE		(4*80)
#define SPF_RECEIVED_SPF_SIZE		(6*80)
#define SPF_SYSLOG_SIZE			(10*80)




/* ********************************************************************* */

/* FYI only -- defaults can't be changed without recompiling the library */
#define SPF_DEFAULT_MAX_DNS_MECH 10	/* DoS limit on SPF mechanisms	*/
#define SPF_DEFAULT_MAX_DNS_PTR	 10	/* DoS limit on PTR records	*/
#define SPF_DEFAULT_MAX_DNS_MX	 10	/* DoS limit on MX records	*/
#define SPF_DEFAULT_SANITIZE	  1
#define SPF_DEFAULT_WHITELIST	  "include:spf.trusted-forwarder.org"
#define SPF_EXP_MOD_NAME	"exp-text"
#define SPF_DEFAULT_EXP		  "Please see http://www.openspf.org/Why?id=%{S}&ip=%{C}&receiver=%{R}"



/* ********************************************************************* */

/** SPF_strerror() translates the SPF error number into a readable string */
const char *SPF_strerror( SPF_errcode_t spf_err );


/** SPF_strresult() translates the SPF result number into a readable string */
const char *SPF_strresult( SPF_result_t result );
/** SPF_strreason() translates the SPF reason number into a readable string */
const char *SPF_strreason( SPF_reason_t reason );

/* This returns the version information library.  Useful if the library
 * is a shared library and may differ from when the application was compiled.
 */
void SPF_get_lib_version( int *major, int *minor, int *patch );

const char *SPF_strrrtype(ns_type rr_type);

#endif
