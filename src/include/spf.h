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

/*
 * we use the in_addr and in6_addr structs all over the place.  Every file
 * that includes spf.h needs them.
 */
/* #include <sys/types.h> */
/* #include <sys/socket.h> */
/* #include <arpa/inet.h> */


#include "spf_lib_version.h"


#define SPF_VERSION 1
#define SPF_VER_STR "v=spf1"


/*
 * object ids for SPF related data
 */

/* SPF record (byte-compiled)		*/
typedef struct SPF_id_struct *SPF_id_t;

/* SPF configuration (IP address, domain names, options, etc.)	*/
typedef struct SPF_config_struct *SPF_config_t;

/* SPF DNS layer configuration		*/
typedef struct SPF_dns_config_struct *SPF_dns_config_t;


/*
 * error codes returned by various SPF functions.  (including SPF_compile()
 * and SPF_id2str(), spf_result(), etc.).
 *
 * The function SPF_strerror() will return a longer explanation of these
 * errors.
 */

typedef int SPF_err_t;

#define SPF_E_SUCCESS		 0	/* No errors			*/
#define SPF_E_NO_MEMORY		 1	/* Out of memory		*/
#define SPF_E_NOT_SPF		 2	/* Could not find a valid SPF record */
#define SPF_E_SYNTAX		 3	/* Syntax error			*/
#define SPF_E_MOD_W_PREF	 4	/* Modifiers can not have prefixes */
#define SPF_E_INVALID_CHAR	 5	/* Invalid character found	*/
#define SPF_E_UNKNOWN_MECH	 6	/* Unknown mechanism found	*/
#define SPF_E_INVALID_OPT	 7	/* Invalid option found		*/
#define SPF_E_INVALID_CIDR	 8	/* Invalid CIDR length		*/
#define SPF_E_MISSING_OPT	 9	/* Required option is missing	*/
#define SPF_E_INTERNAL_ERROR	10	/* Internal programming error	*/
#define SPF_E_INVALID_ESC	11	/* Invalid %-escape character	*/
#define SPF_E_INVALID_VAR	12	/* Invalid macro variable	*/
#define SPF_E_BIG_SUBDOM	13	/* Subdomain truncation depth too large */
#define SPF_E_INVALID_DELIM	14	/* Invalid delimiter character	*/
#define SPF_E_BIG_STRING	15	/* Option string too long	*/
#define SPF_E_BIG_MECH		16	/* Too many mechanisms		*/
#define SPF_E_BIG_MOD		17	/* Too many modifiers		*/
#define SPF_E_BIG_DNS		18	/* Mechanisms used too many DNS lookups */
#define SPF_E_INVALID_IP4	19	/* Invalid IPv4 address literal	*/
#define SPF_E_INVALID_IP6	20	/* Invalid IPv6 address literal	*/
#define SPF_E_INVALID_PREFIX	21	/* Invalid mechanism prefix	*/
#define SPF_E_RESULT_UNKNOWN	22	/* SPF result is \"unknown\"	*/
#define SPF_E_UNINIT_VAR	23	/* Uninitialized variable	*/
#define SPF_E_MOD_NOT_FOUND	24	/* Modifier not found		*/
#define SPF_E_NOT_CONFIG	25	/* Not configured		*/
#define SPF_E_DNS_ERROR		26	/* DNS lookup failure		*/
#define SPF_E_BAD_HOST_IP	27	/* Invalid hostname (possibly an IP address?) */
#define SPF_E_BAD_HOST_TLD	28	/* Hostname has a missing or invalid TLD */
#define SPF_E_MECH_AFTER_ALL	29	/* Mechanisms found after the \"all:\" mechanism will be ignored */
#define SPF_E_NOT_HOST          30      /* Host not found               */


/* ********************************************************************* */

/*
 * SPF record object management
 */

/*
 * These routines take care of creating/destroying/etc. the objects
 * that hold the byte-compiled SPF records.  spfid objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory.  This is true even if the spfid
 * was created for you by a subroutine, such as SPF_compile().
 */

SPF_id_t SPF_create_id( void );		/* create a new spfid		*/
void SPF_reset_id( SPF_id_t spfid );	/* reset the spfid to a newly   */
					/* created state */
void SPF_destroy_id( SPF_id_t spfid );	/* free all memory and clean up.*/
					/* spfid is invalid afterwards  */
SPF_id_t SPF_dup_id( SPF_id_t src_spfid ); /* create a duplicate of a spfid */



/*
 * SPF record byte-compiler
 */

typedef struct
{
    SPF_id_t	spfid;			/* byte compiled SPF record	*/
    SPF_err_t	err;			/* compiler error		*/
    char	*err_msg;		/* first compiler error message	*/
    size_t	err_msg_len;		/* malloc'ed size of err_msg	*/
    int		num_errs;		/* number of errors		*/
    char	**err_msgs;		/* all compilter error info	*/
    size_t	*err_msgs_len;		/* malloc'ed size of err_msgs	*/

    /*
     * these pointers refer to places in the text SPF record and will
     * become invalid when the caller of spf_compile chooses.  This
     * detailed info is available only for the first error message.
     *
     * don't use them if you don't control the text SPF record!
     */
    const char	*expression;	/* the complete mech/mod with the error	*/
    int		expression_len;
    const char	*token;		/* the token within the expression	*/
    int		token_len;
    const char	*error_loc;	/* exact char within the token		*/
} SPF_c_results_t;
    

/*
 * The SPF compiler translates the SPF record in text form (passed in
 * 'record' argument) into a byte-compiled form.  The compiled results are left
 * in the c_results structure as described above.
 *
 * The SPF configuration, while passed as a argument, doesn't effect
 * the byte-compiled results.  It is used only to determine how
 * certain errors are handled, such as the maximum DNS lookups and
 * whether the error messages should be sanitized.
 *
 * An SPF record that is byte-compiled using one configuration can be
 * safely evaluated with a completely different configuration.
 */
SPF_err_t SPF_compile( SPF_config_t spfcid, const char *record, SPF_c_results_t *c_results );

/* finds questionable constructs in the SPF record */
void SPF_lint( SPF_id_t spfid, SPF_c_results_t *c_results );

/* SPF_strerror() translates the SPF error number into a readable string */
const char *SPF_strerror( SPF_err_t spf_err );

/*
 * SPF_verify() can be used to make sure that the byte-compiled object is
 * valid.  This is important when the byte-compiled results are obtained
 * via an outside source, such as a file or via a DNS lookup.  Basically
 * any time you call the SPF_mem2id() function, you probably want to call
 * SPF_verify().
 */
SPF_err_t SPF_verify( SPF_config_t spfcid, SPF_id_t spfid );

/*
 * The SPF optimizer hasn't been written yet, but the intent is to do
 * things like converting 'a' and 'mx' mechanisms into the equivalent
 * ip4/ip6 mechanisms, inlining include mechanisms, etc.
 */
SPF_err_t SPF_optimize( SPF_config_t spfcid, SPF_id_t *dst_spfid, SPF_id_t src_spfid );


/*
 * These routines take care of initializing/freeing/etc. the compiler
 * results structure.  The c_results structure contains malloc'ed
 * variables (including an spfid), so it must be freed when you are
 * finished with it.
 */

void SPF_init_c_results( SPF_c_results_t *c_results );
void SPF_reset_c_results( SPF_c_results_t *c_results );
SPF_c_results_t SPF_dup_c_results( SPF_c_results_t c_results );
void SPF_free_c_results( SPF_c_results_t *c_results );


/* FYI only -- can't be changed without recompiling the library
 * Most error messages are under 80 characters and we don't want
 * bad/malicious input to cause huge error messages */
#define SPF_C_ERR_MSG_SIZE		(2*80)
#define SPF_SMTP_COMMENT_SIZE		(4*80)
#define SPF_RECEIVED_SPF_SIZE		(6*80)
#define SPF_SYSLOG_SIZE			(10*80)




/* ********************************************************************* */

/*
 * SPF configuration object management
 */

/*
 * These routines take care of creating/destroying/etc. the objects
 * that hold the SPF configuration.  spfcid objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 */
SPF_config_t SPF_create_config( void );
void SPF_reset_config( SPF_config_t spfcid );
void SPF_destroy_config( SPF_config_t spfcid );
SPF_config_t SPF_dup_config( SPF_config_t src_spfcid );


/*
 * SPF_destroy_default_config() is useful only at the very end of the
 * program to free up all internally malloc'ed variables.  These
 * variables include such things as the default explanation, that get
 * created automatically,  Calling this will keep valgrind quiet.
 */

void SPF_destroy_default_config( void );


/*
 * The following routines get or set the SPF configuration variables.
 *
 * All of the functions that set configuration return 0 or
 * SPF_E_SUCCESS if there were no errors encountered.
 */


/*
 * The 'ip' variables are for the IP address of the client MTA that is
 * trying to send you email.
 */

/* SPF_set_ip_str() calls the appropriate IPv4/IPv6 routine, depending
 * on the input */
int	SPF_set_ip_str( SPF_config_t spfcid, const char *ip_address );

int	SPF_set_ipv4_str( SPF_config_t spfcid, const char *ipv4_address );
int	SPF_set_ipv4( SPF_config_t spfcid, struct in_addr ipv4 );
struct in_addr  SPF_get_ipv4( SPF_config_t spfcid );

int	SPF_set_ipv6_str( SPF_config_t spfcid, const char *ipv6_address );
int	SPF_set_ipv6( SPF_config_t spfcid, struct in6_addr ipv6 );
struct in6_addr SPF_get_ipv6( SPF_config_t spfcid );

/* SPF_get_client_ver() returns AF_INET or AF_INET6, depending on which
 * kind of IP address was set. */
int	SPF_get_client_ver( SPF_config_t spfcid );


/*
 * SPF needs both an IP address and a domain name to do it's checking.
 * The IP address is set by one of the above routines, but the domain
 * name is not so simple.
 *
 * The domain name is normally obtained from the envelope-from (SMTP
 * MAIL FROM: command), but if that is null (MAIL FROM:<>), then the
 * HELO domain is used (SMTP HELO or EHLO commands).
 *
 * If there is no local part to the envelope-from email address, the
 * name "postmaster" is used instead.  This is the case when the HELO
 * domain has to be used, but it might be able to happen with the
 * envelope-from also, depending on how the MTA works.
 *
 * Whatever the source of the domain name, the SPF spec defines this
 * as the "current domain".  Normally, you wouldn't set this directly,
 * you would call the SPF_set_helo_dom() and SPF_set_env_from()
 * routines.  However, when an SPF record is being evaluated, the
 * current domain is changed when an include or redirect mechanism is
 * executed.
 */

int	SPF_set_helo_dom( SPF_config_t spfcid, const char *helo_domain );
char    *SPF_get_helo_dom( SPF_config_t spfcid );

int	SPF_set_env_from( SPF_config_t spfcid, const char *envelope_from );
char    *SPF_get_env_from( SPF_config_t spfcid );

int	SPF_set_cur_dom( SPF_config_t spfcid, const char *current_domain );
char	*SPF_get_cur_dom( SPF_config_t spfcid );


/*
 * While evaluating the SPF record, the number of mechanisms that
 * require DNS lookups is kept track of.  In order to prevent abusive
 * behavior, there is a limit to how many of these mechanisms can be
 * executed.  It is initial set to the maximum, but you might want to
 * lower it in some cases.
 */

int	SPF_set_max_dns_mech( SPF_config_t spfcid, int max_dns_mech );
int     SPF_get_max_dns_mech( SPF_config_t spfcid );
int	SPF_set_max_dns_ptr( SPF_config_t spfcid, int max_dns_ptr );
int     SPF_get_max_dns_ptr( SPF_config_t spfcid );
int	SPF_set_max_dns_mx( SPF_config_t spfcid, int max_dns_mx );
int     SPF_get_max_dns_mx( SPF_config_t spfcid );


/*
 * Some of the data for error messages and mail headers is obtained
 * from sources on the Internet.  In order to prevent accidental or
 * malicious strings from being passed on, there is an option to
 * sanitize all strings.  The default defined by SPF_DEFAULT_SANITIZE
 */
int	SPF_set_sanitize( SPF_config_t spfcid, int sanitize );
int     SPF_get_sanitize( SPF_config_t spfcid );


/*
 * Part of the Received-SPF: email header requires the domain name of
 * the receiving MTA.
 */

int	SPF_set_rec_dom( SPF_config_t spfcid, const char *receiving_hostname );
char    *SPF_get_rec_dom( SPF_config_t spfcid );


/*
 * When the SPF check fails, an "explanation" string is generated for
 * use by the MTA during the 4xx or 5xx reject code.
 *
 * This explanation string can be any string with macro variables
 * included.  It is first byte compiled, and then the result can be
 * set in the configuration.  If an SPF record does not use the "exp="
 * modifier to specify a more appropriate explanation string, this
 * default explanation string will be used.
 */

SPF_err_t SPF_compile_exp( SPF_config_t spfcid, const char *exp, SPF_c_results_t *c_results );
int SPF_set_exp( SPF_config_t spfcid, SPF_c_results_t c_results );


/*
 * Several of the SPF specifications support a "local policy" option.
 * This is both very important, and not particularly obvious how it
 * works.
 *
 * Email may come from many sources, sometimes these sources are not
 * direct, and not all of these indirect sources correctly rewrite the
 * envelope-from to specify the new domain that is resending the
 * email.  This can happen on incorrectly configured mailing lists, or
 * from people who have set up unix-like .forward files.
 *
 * Often, you want to accept these emails, even if they would
 * technically fail the SPF check.  So, you can set up a "local
 * policy" that lists these sources of known-ok emails.  If a local
 * policy is set, it will allow you to whitelist these sources.  There
 * is a default globally maintained whitelist of known trusted email
 * forwarders that is generally a good idea to use.
 * 
 * SPF checks that pass due to local policies will be noted in the
 * messages generated from SPF_result().  As such, it is best if the
 * local policy option is check only right before the SPF check is
 * sure to fail.  SPF records that say that a domain never sends email
 * should not do any checking of the local policy.
 *
 * The exact spot in the evaluation of the SPF record was defined in a
 * message sent to the SPF-devel mailing list.  It said in part:
 *
 * Philip Gladstone says:
 * Message-ID: <400B56AB.30702@gladstonefamily.net>
 * Date: Sun, 18 Jan 2004 23:01:47 -0500
 *
 *
 * I think that the localpolicy should only be inserted if the
 * final mechanism is '-all', and it should be inserted after
 * the last mechanism which is not '-'.
 *
 * Thus for the case of 'v=spf1 +a +mx -all', this would be
 * interpreted as 'v=spf1 +a +mx +localpolicy -all'. Whereas
 * 'v=spf1 -all' would remain the same (no non-'-'
 * mechanism). 'v=spf1 +a +mx -exists:%stuff -all' would
 * become 'v=spf1 +a +mx +localpolicy -exists:%stuff -all'.
 *
 *
 * This local policy string can be any string with macro variables
 * included.  It is first byte compiled, and then the result can be
 * set in the configuration.  
 */
	

SPF_err_t SPF_compile_local_policy( SPF_config_t spfcid, const char *spf_record,
				    int use_default_whitelist,
				    SPF_c_results_t *c_results );
int	SPF_set_local_policy( SPF_config_t spfcid,
			  SPF_c_results_t c_results );
SPF_c_results_t SPF_get_local_policy( SPF_config_t spfcid );

/*
 * The SPF library allows a certain amount of debugging output to be
 * generated for help in determining why things succeeded or failed.
 * Currently, only the following debug levels are implemented:
 *
 * 0	Be completely silent, no debugging information will be generated.
 * 1    Moderate amount of debugging information.
 * 2    Include some detailed information about the DNS lookups.  Usually
 *      this is not needed.
 */

int	SPF_set_debug( SPF_config_t spfcid, int debug_level );
int     SPF_get_debug( SPF_config_t spfcid );


/* FYI only -- defaults can't be changed without recompiling the library */
#define SPF_DEFAULT_EXP		  "Please see http://spf.pobox.com/why.html?sender=%{S}&ip=%{C}&receiver=%{R}"
#define SPF_DEFAULT_MAX_DNS_MECH 10	/* DoS limit on SPF mechanisms	*/
#define SPF_DEFAULT_MAX_DNS_PTR	  5	/* DoS limit on PTR records	*/
#define SPF_DEFAULT_MAX_DNS_MX	  5	/* DoS limit on MX records	*/
#define SPF_DEFAULT_SANITIZE	  1
#define SPF_DEFAULT_WHITELIST	  "include:spf.trusted-forwarder.org"



/* ********************************************************************* */

/*
 * Results from an SPF check
 */

/*
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
typedef int SPF_result_t;

#define SPF_RESULT_PASS		0	/* +				*/
#define SPF_RESULT_FAIL		1	/* -				*/
#define SPF_RESULT_SOFTFAIL	2	/* ~				*/
#define SPF_RESULT_NEUTRAL	3	/* ?				*/
#define SPF_RESULT_UNKNOWN	4	/* permanent error		*/
#define SPF_RESULT_ERROR	5	/* temp error			*/
#define SPF_RESULT_NONE		6	/* no SPF record exists		*/


/*
 * The reason that the result was returned
 *
 * This is what triggered the SPF result.  Usually, it is a mechanism in the
 * SPF record that causes the result, but if it was something else, the
 * calling program will often want to take a different action or issue
 * a different message.
 */
typedef int SPF_reason_t;

#define SPF_REASON_NONE		0
#define SPF_REASON_LOCALHOST	1	/* localhost always gets a free ride */
#define SPF_REASON_LOCAL_POLICY	2	/* local policy caused the match */
#define SPF_REASON_MECH		3	/* mechanism caused the match	*/
#define SPF_REASON_DEFAULT	4	/* ran off the end of the rec	*/
#define SPF_REASON_2MX		5	/* sent from a secondary MX	*/


/* FIXME  the relationships between result, reason and err is too murky */


/*
 * The SPF_output_t structure contains the results from an SPF check.  These
 * results can then be used by the calling program to reject the email, or
 * add headers to the email, or whatever is appropriate.
 *
 * result	See SPF_result_t for details
 * reason	See SPF_reason_t for details
 * err		See SPF_err_t for details
 *
 * err_msg	The first error message from compiling/evaluating the record
 * num_errs	The number of error messages
 * err_msgs	All of the error messages from compiling/evaluating the record
 *
 * smtp_comment	The MTA should return this message when rejecting an email
 *		due to the SPF check failure.  This comment is created via
 *		the explanation modifier (exp=) or a default explanation
 *		if no modifier is found on the SPF record.  See section
 *		5.2 of the SPF spec for details.
 * received_spf The MTA should add this header to the email at the very top
 *		of the headers.  (Before the Received: header generated by
 *		this MTA)  See section 6.3 of the SPF spec for details.
 * header_comment  This is the "comment" part of the received_spf header.
 *              This is useful if you want to build your onw received_spf
 *              header.
 */

typedef struct
{
    SPF_result_t	result;		/* pass/fail/softfail/etc.	*/
    SPF_reason_t	reason;		/* mech match, local policy, etc*/
    SPF_err_t		err;		/* DNS error, out of memory, etc*/

    char		*err_msg;	/* first syntax error info	*/
    int			num_errs;	/* number of errors		*/
    char		**err_msgs;	/* all syntax error info	*/

    char		*smtp_comment;	/* MTA rejection explanation	*/
    char		*received_spf;	/* to be added to the email	*/
    char		*header_comment; /* comment part of received_spf*/
} SPF_output_t;
    
/*
 * These routines take care of initializing/freeing/etc. the SPF check
 * output structure.  The output structure contains malloc'ed
 * variables, so it must be freed when you are finished with it.
 */

void SPF_init_output( SPF_output_t *output );
SPF_output_t SPF_dup_output( SPF_output_t output );
void SPF_free_output( SPF_output_t *output );



/* SPF_result() just calls SPF_result_id() with the SPF record found
 * using the envelope from or HELO domain in the SPF_config_t. */

/*
 * The SPF_result() function does most of the real, important work.
 *
 * SPF_result() checks the IP address and the envelope-from (or HELO
 * domain) as was configured using the spfcid variable and sees if it
 * is valid.  It returns all the info that the caller will need to use
 * the SPF check results.  See the description of the structure
 * SPF_output_t for details about the return value of SPF_result() and
 * how they should be used.
 * 
 * It may use the DNS configuration to fetch additional information.
 *
 * Actually, SPF_result() is just an easy-to-use wrapper around
 * SPF_get_spf(), SPF_eval_id() and SPF_result_comments().
 */
SPF_output_t SPF_result( SPF_config_t spfcid, SPF_dns_config_t spfdcid );

/*
 * SPF_result_helo() is just like SPF_result(), only it checks the
 * HELO domain instead of the envelope from
 */
SPF_output_t SPF_result_helo( SPF_config_t spfcid, SPF_dns_config_t spfdcid );


/*
 * SPF_result_2mx() does everything that SPF_result() does, but it first
 * checks to see if the sending system is a recognized MX
 * secondary for the email recipient. If so, then it returns "pass"
 * and does not perform the SPF query. Note that the sending
 * system may be a MX secondary for some (but not all) of the
 * recipients for a multi-recipient message, which is why
 * SPF_result_2mx may be called many times with the final result being
 * obtained from SPF_result_2mx_msg().
 *
 * In effect, SPF_result_2mx() adds the mechanism "mx:<rcpt-to domain>" to
 * the beginning of the SPF record for the mail from domain.
 *
 * If you do not know what a secondary MX is, you probably don't have
 * one.  Use the SPF_result() function instead.
 * 
 */

SPF_output_t SPF_result_2mx( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
			     const char *rcpt_to );
SPF_output_t SPF_result_2mx_msg( SPF_config_t spfcid,
				 SPF_dns_config_t spfdcid );

/*
 * SPF_eval_id() is a low-level runction that does the actual SPF
 * checking.
 *
 * It takes the IP address and domain, the SPF record, and a way to do
 * the DNS lookups that the SPF record may require, does the
 * evaluation and returns the results.
 *
 * The IP address and domain are found found in the SPF config.  The
 * SPF record is found in spfid variable.  The way to do the DNS
 * lookups is found in the DNS config.
 *
 * The three different inputs can be mixed and matched in any way you
 * want.  You can take the same SPF config and evaluate many different
 * SPF records with it, or you can take the same SPF record and
 * evaluate many different configurations with it.  (And the same goes
 * for changing the DNS config whenever you want.)
 *
 * In addition, SPF_eval_id() gets passed a few bookkeeping variables.
 *
 * The use_local_policy variable determines if the local_policy
 * mechanisms should be applied.  Normally, the top level call to
 * SPF_eval_id() would pass TRUE, but recursive calls caused by the
 * include: mechanism would pass FALSE.
 *
 * The use_helo variable determins if the "responsible sender" (as
 * defined in the SPF spec) should be the HELO domain instead of the
 * envelope-from.  Normally, the HELO domain is used as a fallback if
 * the envelope-from is empty, but this variable lets you explicitly
 * check the HELO domain.
 *
 * The "num_dns_mech" keeps track of the number of mechanisms that
 * have required DNS lookups.  Normally, the top level call to
 * SPF_eval_id() pass NULL for num_dns_mech, while recursive calls
 * caused by the include: mechanism pass an internal counter.
 */

SPF_output_t SPF_eval_id( SPF_config_t spfcid, SPF_id_t spfid,
			  SPF_dns_config_t spfdcid, 
			  int use_local_policy, int use_helo,
			  int *num_dns_mech );


/*
 * SPF_result_comments filles out the smtp_comment (if appropriate),
 * received_spf and header_comment fields of the SPF_output_t
 * structure.
 */
void SPF_result_comments( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
			  SPF_c_results_t c_results, SPF_output_t *output );


/* SPF_smtp_comment() may requre DNS lookups, so call on when needed */
char *SPF_smtp_comment( SPF_config_t spfcid, SPF_id_t spfid, SPF_dns_config_t spfdcid, SPF_output_t output );

/* SPF_received_spf() depends on the header_comment being set */
char *SPF_received_spf( SPF_config_t spfcid, SPF_c_results_t c_results, SPF_output_t output );

char *SPF_header_comment( SPF_config_t spfcid, SPF_output_t output );


/* SPF_strresult() translates the SPF result number into a readable string */
const char *SPF_strresult( SPF_result_t result );
/* SPF_strreason() translates the SPF reason number into a readable string */
const char *SPF_strreason( SPF_reason_t reason );

/* Extract value of modifier from the SPF record.  The value will have
 * any macro-variables expanded. */
SPF_err_t SPF_find_mod_value( SPF_config_t spfcid, SPF_id_t spfid,
			      SPF_dns_config_t spfdcid, const char *mod_name,
			      char **buf, size_t *buf_len );
SPF_err_t SPF_find_mod_cidr( SPF_config_t spfcid, SPF_id_t spfid,
			     SPF_dns_config_t spfdcid, const char *mod_name,
			     int *ipv4_cidr, int *ipv6_cidr );


/* ********************************************************************* */

/*
 * misc functions
 */

/* converts the byte-compiled SPF record between the library format and
 * a network portable block of data */
SPF_err_t SPF_id2mem( void *dst_mem, int *dst_len, SPF_id_t src_spfid );
SPF_err_t SPF_mem2id( SPF_id_t dst_spfid, void *src_mem, int src_len );

/* convert the byte-compiled SPF record in the equivalent text format.
 * The results may not exactly match the original text record before
 * it was compiled due to changes in whitespaces, optional arguments,
 * etc. */
SPF_err_t SPF_id2str( char **dst_rec, size_t *dst_len, SPF_id_t src_spfid );
/* SPF_err_t SPF_str2id()   See: SPF_compile() */

/* print the byte-compiled SPF record, along with a little debugging info */
void SPF_print( SPF_id_t spfid );


/* Get an SPF record from the given domain and return the compiled results.
 * If the domain is NULL, SPF_get_spf() will use the envelope-from domain
 * if it exists, or the HELO domain as the last resort.
 */
SPF_err_t SPF_get_spf( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
		       const char *domain, SPF_c_results_t *c_results );

/* Get an SPF explanation string from the given domain and return the
 * compiled results */ 
SPF_err_t SPF_get_exp( SPF_config_t spfcid, SPF_id_t spfid,
		       SPF_dns_config_t spfdcid,
 		       char **buf, size_t *buf_len );


/* The client domain is the validated domain name of the client IP
 * address.  This is not just the domain name(s) found in the reverse
 * DNS tree, but involves checking to make sure these name(s) use the
 * client IP address.  The complete validation procedure is described
 * in section 5.4 of the SPF spec.
 */
char *SPF_get_client_dom( SPF_config_t spfcid, SPF_dns_config_t spfdcid );

/* Since determining the client domain can be somewhat expensive, you
 * can explicitly make sure it is set, rather than just waiting until
 * SPF_get_client_dom() is called. */
void SPF_set_client_dom( SPF_config_t spfcid, SPF_dns_config_t spfdcid );


/* This returns the version information library.  Useful if the library
 * is a shared library and may differ from when the application was compiled.
 */
void SPF_get_lib_version( int *major, int *minor, int *patch );


/*
 * Error messages and warnings generated internally by the library call
 * these routines.  By default, the messages go to stderr, but you can
 * define your own routines to deal with the messages instead.
 */

#include <stdarg.h>


#define SPF_error(errmsg) SPF_errorx( __FILE__, __LINE__, "%s", errmsg )
void SPF_errorx( const char *file, int line, const char *format, ... ) __attribute__ ((noreturn)) __attribute__ ((format (printf, 3, 4)));
void SPF_errorx2( const char *format, ... );
void SPF_errorv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((noreturn)) __attribute__ ((format (printf, 3, 0)));

#define SPF_warning(errmsg) SPF_warningx( __FILE__, __LINE__, "%s", errmsg )
void SPF_warningx( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_warningx2( const char *format, ... );
void SPF_warningv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));

#define SPF_info(errmsg) SPF_infox( __FILE__, __LINE__, "%s", errmsg )
void SPF_infox( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_infox2( const char *format, ... );
void SPF_infov( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));

#define SPF_debug(errmsg) SPF_debugx( __FILE__, __LINE__, "%s", errmsg )
void SPF_debugx( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_debugx2( const char *format, ... );
void SPF_debugv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));


#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 199901L

#define SPF_errorf(format, ... ) SPF_errorx( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_warningf(format, ... ) SPF_warningx( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_infof(format, ... ) SPF_infox( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_debugf(format, ... ) SPF_debugx( __FILE__, __LINE__, format, __VA_ARGS__ )

#elif defined( __GNUC__ )

#define SPF_errorf(format... ) SPF_errorx( __FILE__, __LINE__, format )
#define SPF_warningf(format... ) SPF_warningx( __FILE__, __LINE__, format )
#define SPF_infof(format... ) SPF_infox( __FILE__, __LINE__, format )
#define SPF_debugf(format... ) SPF_debugx( __FILE__, __LINE__, format )

#else

#define SPF_errorf	SPF_errorx2
#define SPF_warningf	SPF_warningx2
#define SPF_infof	SPF_infox2
#define SPF_debugf	SPF_debugx2

#endif


/* These message handler routines print to stderr or stdout, as appropriate. */

void SPF_error_stdio( const char *file, int line, const char *errmsg ) __attribute__ ((noreturn));
void SPF_warning_stdio( const char *file, int line, const char *errmsg );
void SPF_info_stdio( const char *file __attribute__ ((unused)), int line __attribute__ ((unused)), const char *errmsg );
void SPF_debug_stdio( const char *file, int line, const char *errmsg );


/* These message handler routines send messages to syslog */

void SPF_error_syslog( const char *file, int line, const char *errmsg ) __attribute__ ((noreturn));
void SPF_warning_syslog( const char *file, int line, const char *errmsg );
void SPF_info_syslog( const char *file __attribute__ ((unused)), int line __attribute__ ((unused)), const char *errmsg );
void SPF_debug_syslog( const char *file, int line, const char *errmsg );

#if 0
    /* to use the syslog routines, add code such as: */
    openlog(logPrefix,LOG_PID|LOG_CONS|LOG_NDELAY|LOG_NOWAIT,LOG_MAIL);

    SPF_error_handler = SPF_error_syslog;
    SPF_warning_handler = SPF_warning_syslog;
    SPF_info_handler = SPF_info_syslog;
    SPF_debug_handler = SPF_debug_syslog;
#endif

/* FYI only -- can't be changed without recompiling the library */
#define SPF_DEFAULT_ERROR_HANDLER	SPF_error_stdio
#define SPF_DEFAULT_WARNING_HANDLER	SPF_warning_stdio
#define SPF_DEFAULT_INFO_HANDLER	SPF_info_stdio
#define SPF_DEFAULT_DEBUG_HANDLER	SPF_debug_stdio


/*
 * You can assign these global function pointers to whatever routines
 * you want to handle the various types of messages.  Setting them to NULL
 * will cause the messages to be ignored.
 */
 
extern void (*SPF_error_handler)( const char *, int, const char * ) __attribute__ ((noreturn));
extern void (*SPF_warning_handler)( const char *, int, const char * );
extern void (*SPF_info_handler)( const char *, int, const char * );
extern void (*SPF_debug_handler)( const char *, int, const char * );



#endif
