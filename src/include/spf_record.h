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




#ifndef INC_SPF_RECORD
#define INC_SPF_RECORD

typedef struct SPF_record_struct SPF_record_t;
typedef struct SPF_macro_struct SPF_macro_t;

#include "spf_response.h"
#include "spf_request.h"
#include "spf_server.h"

/*
 * Compiled SPF record
 */

/*
 * The compiled form of the SPF record is as follows:
 *
 * * A four byte header which contains the version, and information
 *   about the mechanisms and modifiers
 *
 * * Mechanism information, repeated once for each mechanism
 *
 *   * A two byte header describing the mechanism
 *
 *   * Data associated with the mechanism.  This can be of several forms
 *
 *     * ip4/ip6 have a fixed format data field, cidr length is in
 *       the mechanism's parm_len field
 *
 *     * Mechanisms that allow a macro-string 
 *
 *       * Optional two byte CIDR length structure.  (Yes, this is at
 *         the beginning, rather than at the end.)
 *
 *       * tokenized data description blocks that can be either:
 *
 *         * two byte macro variable description
 *
 *         * two byte string description, followed by the string
 *
 *   * Modifier information, repeated once for each modifier
 *
 *     * two byte header describing the modifier
 *
 *     * name of the modifier
 *
 *     * tokenized data description blocks that can be either:
 *
 *         * two byte macro variable description
 *
 *         * two byte string description, followed by the string
 */


#define	SPF_MAX_STR_LEN		255	/* limits on SPF_data_str_t.len, */
					/* SPF_mod_t.name_len and	*/
				        /* SPF_mod_t.data_len		*/

#define SPF_MAX_MECH_LEN	511
#define SPF_MAX_MOD_LEN		511











/*
 * Tokens and macros to be expanded in SPF_data_str_t in mech/mod
 */

#define PARM_LP_FROM	 0		/* l = local-part of envelope-sender */
#define PARM_ENV_FROM	 1		/* s = envelope-sender		*/
#define PARM_DP_FROM	 2		/* o = envelope-domain		*/
#define PARM_CUR_DOM	 3		/* d = current-domain		*/
#define PARM_CLIENT_IP	 4		/* i = SMTP client IP		*/
#define PARM_CLIENT_IP_P 5		/* c = SMTP client IP (pretty)	*/
#define PARM_TIME	 6		/* t = time in UTC epoch secs	*/
#define PARM_CLIENT_DOM	 7		/* p = SMTP client domain name	*/
#define PARM_CLIENT_VER	 8		/* v = IP ver str - in-addr/ip6	*/
#define PARM_HELO_DOM	 9		/* h = HELO/EHLO domain		*/
#define PARM_REC_DOM	10		/* r = receiving domain		*/
#define PARM_CIDR	11		/* CIDR lengths (IPv4 and v6)	*/
#define PARM_STRING	12		/* literal string		*/


typedef
struct SPF_data_str_struct
{
    unsigned char	parm_type;
    unsigned char	len;
    /* text: (char[len]) follows */
} SPF_data_str_t;


typedef
struct SPF_data_var_struct
{
    unsigned char	parm_type;
    unsigned char	num_rhs;	/* chop subdomain name		*/
    unsigned short	rev:	     1;	/* reverse 			*/
    unsigned short	url_encode:  1;	/* do URL encoding		*/
    unsigned short	delim_dot:   1;	/* delimiter char: .		*/
    unsigned short	delim_dash:  1;	/* delimiter char: -		*/
    unsigned short	delim_plus:  1;	/* delimiter char: +		*/
    unsigned short	delim_equal: 1;	/* delimiter char: =		*/
    unsigned short	delim_bar:   1;	/* delimiter char: |		*/
    unsigned short	delim_under: 1;	/* delimiter char: _		*/
} SPF_data_var_t;

typedef
struct SPF_data_cidr_struct
{
    unsigned char	parm_type;
    unsigned char	ipv4;
    unsigned char	ipv6;
    unsigned char	__unused0;
    /* If we are the first operand in an IP4 or IP6 instruction then
     * addr: (struct in[6]_addr) follows */
} SPF_data_cidr_t;

typedef
union SPF_data_union
{
    SPF_data_var_t	dv;
    SPF_data_str_t	ds;
    SPF_data_cidr_t	dc;
} SPF_data_t;



/*
 * Prefixes
 */
#define PREFIX_PASS		SPF_RESULT_PASS
#define PREFIX_FAIL		SPF_RESULT_FAIL
#define PREFIX_SOFTFAIL	SPF_RESULT_SOFTFAIL
#define PREFIX_NEUTRAL  SPF_RESULT_NEUTRAL
#define PREFIX_UNKNOWN	SPF_RESULT_PERMERROR

/*
 * Mechanisms
 */
#define MECH_UNKNOWN	0	/* Return PERMERROR */
#define MECH_A		1
#define MECH_MX		2
#define MECH_PTR	3
#define MECH_INCLUDE	4
#define MECH_IP4	5
#define MECH_IP6	6
#define MECH_EXISTS	7
#define MECH_ALL	8  
#define MECH_REDIRECT	9

typedef
struct SPF_mech_struct
{
    unsigned char	prefix_type;	/* PASS/FAIL/... */
    unsigned char	mech_type;	/* A/MX/PTR/... */
    unsigned short	mech_len;	/* bytes of data or cidr len */
    /* data: (SPF_data_t[] = char[mech_len]) follows */
} SPF_mech_t;


/*
 * Modifiers
 */
typedef
struct SPF_mod_struct
{
    unsigned short	name_len;
    unsigned short	data_len;
    /* name: (char[name_len]) follows */
    /* data: (SPF_data_t[] = char[data_len]) follows */
} SPF_mod_t;



/*
 * Compiled SPF records as used internally by libspf2
 */

struct SPF_record_struct
{
	SPF_server_t	*spf_server;

    /* Header */
    unsigned char	 version;		/* SPF spec version number	*/
    unsigned char	 num_mech;		/* number of mechanisms 	*/
    unsigned char	 num_mod;		/* number of modifiers		*/
    unsigned char	 num_dns_mech;	/* number of DNS mechanisms	*/

    /* Data */
    SPF_mech_t		*mech_first;	/* buffer for mechanisms	*/
    size_t			 mech_size;		/* malloc'ed size			*/
    size_t			 mech_len;		/* used size (non-network format) */

    SPF_mod_t		*mod_first;		/* buffer for modifiers		*/
    size_t			 mod_size;		/* malloc'ed size			*/
    size_t			 mod_len;		/* used size (non-network format) */
};

struct SPF_macro_struct
{
    unsigned int	macro_len;	/* bytes of data */
    /* data: (SPF_data_t[] = char[macro_len]) follows */
};


/* In spf_record.c */
SPF_record_t	*SPF_record_new(SPF_server_t *spf_server,
			const char *text);
void			 SPF_record_free(SPF_record_t *rp);
void			 SPF_macro_free(SPF_macro_t *mac);
#if 0	/* static */
SPF_errcode_t	 SPF_record_find_mod_data(SPF_server_t *spf_server,
			SPF_record_t *spf_record,
			const char *mod_name,
			SPF_data_t **datap, size_t *datalenp);
#endif
SPF_errcode_t	 SPF_record_find_mod_value(SPF_server_t *spf_server,
			SPF_request_t *spf_request,
			SPF_response_t *spf_response,
			SPF_record_t *spf_record,
			const char *mod_name,
			char **bufp, size_t *buflenp);

/* In spf_compile.c */
SPF_errcode_t	 SPF_record_compile(SPF_server_t *spf_server,
			SPF_response_t *spf_response,
			SPF_record_t **spf_recordp,
		    const char *record);
SPF_errcode_t	 SPF_record_compile_macro(SPF_server_t *spf_server,
			SPF_response_t *spf_response,
			SPF_macro_t **spf_macrop,
			const char *record);
/* In spf_interpret.c */
SPF_errcode_t	 SPF_record_interpret(
			SPF_record_t *spf_record,
			SPF_request_t *spf_request,
			SPF_response_t *spf_response,
			int depth);
/* In spf_expand.c */
SPF_errcode_t	 SPF_record_expand_data(SPF_server_t *spf_server,
			SPF_request_t *spf_request,
			SPF_response_t *spf_response,
			SPF_data_t *data, size_t data_len,
			char **bufp, size_t *buflenp);
/* In spf_print.c */
SPF_errcode_t	 SPF_record_print(SPF_record_t *spf_record);
SPF_errcode_t	 SPF_record_stringify(SPF_record_t *spf_record,
			char **bufp, size_t *buflenp);

#endif
