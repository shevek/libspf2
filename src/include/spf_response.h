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

#ifndef INC_SPF_RESPONSE
#define INC_SPF_RESPONSE

/**
 * Results from an SPF check
 *
 * The results of the SPF check (as defined by the official SPF spec)
 *
 * To quote from doc/draft-mengwong-spf-00.txt Section 3:
 *
 *     3. SPF Record Evaluation
 *     
 *        An SPF client evaluates an SPF record and produces one of seven
 *        results:
 *     
 *          None: The domain does not publish SPF data.
 *     
 *          Neutral (?): The SPF client MUST proceed as if a domain did not
 *          publish SPF data.  This result occurs if the domain explicitly
 *          specifies a "?" value, or if processing "falls off the end" of
 *          the SPF record.
 *     
 *          Pass (+): the message meets the publishing domain's definition of
 *          legitimacy.  MTAs proceed to apply local policy and MAY accept or
 *          reject the message accordingly.
 *     
 *          Fail (-): the message does not meet a domain's definition of
 *          legitimacy.  MTAs MAY reject the message using a permanent
 *          failure reply code.  (Code 550 is RECOMMENDED.  See RFC2821
 *          section 7.1.)
 *     
 *          Softfail (~): the message does not meet a domain's strict
 *          definition of legitimacy, but the domain cannot confidently state
 *          that the message is a forgery.  MTAs SHOULD accept the message
 *          but MAY subject it to a higher transaction cost, deeper scrutiny,
 *          or an unfavourable score.
 *     
 *        There are two error conditions, one temporary and one permanent.
 *     
 *          Error: indicates an error during lookup; an MTA MAY reject the
 *          message using a transient failure code, such as 450.
 *     
 *          Unknown: indicates incomplete processing: an MTA MUST proceed as
 *          if a domain did not publish SPF data.
 *     
 *        When SPF-aware SMTP receivers accept a message, they SHOULD prepend a
 *        Received-SPF header.  See section 6.
 *     
 *        SPF clients MUST use the algorithm described in this section
 *        or its functional equivalent.
 *        
 *        If an SPF client encounters a syntax error in an
 *        SPF record, it must terminate processing and return a result
 *        of "unknown".
 *
 *
 * note: SPF_RESULT_* values are constrained by the internal PREFIX_* values
 */


typedef
enum SPF_result_enum {
	SPF_RESULT_INVALID = 0,		/* We should never return this. */
	SPF_RESULT_NEUTRAL,
	SPF_RESULT_PASS,
	SPF_RESULT_FAIL,
	SPF_RESULT_SOFTFAIL,

	SPF_RESULT_NONE,
	SPF_RESULT_TEMPERROR,
	SPF_RESULT_PERMERROR
} SPF_result_t;

/**
 * The reason that the result was returned
 *
 * This is what triggered the SPF result.  Usually, it is a mechanism in the
 * SPF record that causes the result, but if it was something else, the
 * calling program will often want to take a different action or issue
 * a different message.
 */
typedef
enum SPF_reason_enum {
	SPF_REASON_NONE			= 0
,	SPF_REASON_FAILURE
,	SPF_REASON_LOCALHOST	/* localhost always gets a free ride */
,	SPF_REASON_LOCAL_POLICY	/* local policy caused the match */
,	SPF_REASON_MECH			/* mechanism caused the match	*/
,	SPF_REASON_DEFAULT		/* ran off the end of the rec	*/
,	SPF_REASON_2MX			/* sent from a secondary MX	*/
} SPF_reason_t;


/**
 * error codes returned by various SPF functions.  (including SPF_compile()
 * and SPF_id2str(), spf_result(), etc.).
 *
 * The function SPF_strerror() will return a longer explanation of these
 * errors.
 */

typedef
enum SPF_errcode_t {
	SPF_E_SUCCESS	 = 0	/* No errors			*/
,	SPF_E_NO_MEMORY			/* Out of memory		*/
,	SPF_E_NOT_SPF			/* Could not find a valid SPF record */
,	SPF_E_SYNTAX			/* Syntax error			*/
,	SPF_E_MOD_W_PREF		/* Modifiers can not have prefixes */
,	SPF_E_INVALID_CHAR		/* Invalid character found	*/
,	SPF_E_UNKNOWN_MECH		/* Unknown mechanism found	*/
,	SPF_E_INVALID_OPT		/* Invalid option found		*/
,	SPF_E_INVALID_CIDR		/* Invalid CIDR length		*/
,	SPF_E_MISSING_OPT		/* Required option is missing	*/
,	SPF_E_INTERNAL_ERROR	/* Internal programming error	*/
,	SPF_E_INVALID_ESC		/* Invalid %-escape character	*/
,	SPF_E_INVALID_VAR		/* Invalid macro variable	*/
,	SPF_E_BIG_SUBDOM		/* Subdomain truncation depth too large */
,	SPF_E_INVALID_DELIM		/* Invalid delimiter character	*/
,	SPF_E_BIG_STRING		/* Option string too long	*/
,	SPF_E_BIG_MECH			/* Too many mechanisms		*/
,	SPF_E_BIG_MOD			/* Too many modifiers		*/
,	SPF_E_BIG_DNS			/* Mechanisms used too many DNS lookups */
,	SPF_E_INVALID_IP4		/* Invalid IPv4 address literal	*/
,	SPF_E_INVALID_IP6		/* Invalid IPv6 address literal	*/
,	SPF_E_INVALID_PREFIX	/* Invalid mechanism prefix	*/
,	SPF_E_RESULT_UNKNOWN	/* SPF result is \"unknown\"	*/
,	SPF_E_UNINIT_VAR		/* Uninitialized variable	*/
,	SPF_E_MOD_NOT_FOUND		/* Modifier not found		*/
,	SPF_E_NOT_CONFIG		/* Not configured		*/
,	SPF_E_DNS_ERROR			/* DNS lookup failure		*/
,	SPF_E_BAD_HOST_IP		/* Invalid hostname (an IP address?) */
,	SPF_E_BAD_HOST_TLD		/* Hostname has a missing or invalid TLD */
,	SPF_E_MECH_AFTER_ALL	/* Mechanisms found after the \"all:\"
								mechanism will be ignored */
,	SPF_E_INCLUDE_RETURNED_NONE	/* If an include recursive query returns none it's a perm error */
,	SPF_E_RECURSIVE			/* Recursive include */
} SPF_errcode_t;

typedef
struct SPF_error_struct
{
	SPF_errcode_t	 code;
	char			*message;
	char			 is_error;
} SPF_error_t;

typedef struct SPF_response_struct SPF_response_t;

#include "spf.h"
#include "spf_request.h"

struct SPF_response_struct {
	/* Structure variables */
	SPF_request_t	*spf_request;
	SPF_record_t	*spf_record_exp;

	/* The answer itself. */
	SPF_result_t	 result;
	SPF_reason_t	 reason;
	SPF_errcode_t	 err;

	char			*received_spf;
	char			*received_spf_value;
	char			*header_comment;
	char			*smtp_comment;
	char			*explanation;

	/* The errors */
	SPF_error_t		*errors;
	unsigned short	 errors_size;		/* Allocated */
	unsigned short	 errors_length;		/* Used */
	unsigned short	 num_errors;		/* Excluding warnings */

	/* Stuff which lets us get there. */
	int				 num_dns_mech;
};


SPF_response_t	*SPF_response_new(SPF_request_t *spf_request);
void			 SPF_response_free(SPF_response_t *rp);
SPF_response_t	*SPF_response_combine(SPF_response_t *main,
					SPF_response_t *r2mx);

	/* Query functions for elements of the result */
SPF_result_t	 SPF_response_result(SPF_response_t *rp);
SPF_reason_t	 SPF_response_reason(SPF_response_t *rp);
SPF_errcode_t	 SPF_response_errcode(SPF_response_t *rp);
const char		*SPF_response_get_received_spf(SPF_response_t *rp);
const char		*SPF_response_get_received_spf_value(SPF_response_t*rp);
const char		*SPF_response_get_header_comment(SPF_response_t *rp);
const char		*SPF_response_get_smtp_comment(SPF_response_t *rp);
const char		*SPF_response_get_explanation(SPF_response_t *rp);

	/* How many warnings were generated? */
int				 SPF_response_messages(SPF_response_t *rp);
	/* How many errors were generated? */
int				 SPF_response_errors(SPF_response_t *rp);
	/* Errors + warnings */
int				 SPF_response_warnings(SPF_response_t *rp);
	/* Get an individual message */
SPF_error_t		*SPF_response_message(SPF_response_t *rp, int idx);

SPF_errcode_t	 SPF_error_code(SPF_error_t *err);
const char *	 SPF_error_message(SPF_error_t *err);
char			 SPF_error_errorp(SPF_error_t *err);

	/* Internal functions for adding errors. */

SPF_errcode_t	 SPF_response_add_error_ptr(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *text, const char *tptr,
					const char *format, ...);
SPF_errcode_t	 SPF_response_add_error_idx(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *text, int idx,
					const char *format, ...);
SPF_errcode_t	 SPF_response_add_error(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *format, ...);
SPF_errcode_t	 SPF_response_add_warn_ptr(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *text, const char *tptr,
					const char *format, ...);
SPF_errcode_t	 SPF_response_add_warn_idx(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *text, int idx,
					const char *format, ...);
SPF_errcode_t	 SPF_response_add_warn(SPF_response_t *rp,
					SPF_errcode_t code,
					const char *format, ...);

#endif
