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




#ifndef INC_SPF_INTERNAL
#define INC_SPF_INTERNAL


#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define array_elem(x) ((long int)(sizeof( x ) / sizeof( *x )))



/*
 * SPF configuration data
 */
typedef struct 
{
    /*
     * user settable options
     */
    int		client_ver;		/* AF_INET/AF_INET6		*/
    struct in_addr	ipv4;		/* client (sending) MTA IP addr */
    struct in6_addr	ipv6;		/* client (sending) MTA IP addr */
    char	*env_from;		/* envelope-from/MAIL FROM:	*/
    char	*helo_dom;		/* domain name from HELO cmd	*/
    char	*rec_dom;		/* receiving MTA domain name	*/

    char	*rcpt_to_dom;		/* RCPT TO: domain for 2mx	*/
    int		found_2mx;		/* RCPT TO: for 2mx found	*/
    int		found_non_2mx;		/* RCPT TO: not for 2mx found	*/
    SPF_output_t	output_2mx;	/* msg to return at DATA time	*/

    int		max_dns_mech;		/* DoS limit on SPF mechanisms	*/
    int		max_dns_ptr;		/* DoS limit on PTR records	*/
    int		max_dns_mx;		/* DoS limit on MX records	*/
    int		sanitize;		/* limit charset in messages	*/
    int		debug;			/* print debug info		*/

    /* must be assigned last because compiling uses the config */
    SPF_c_results_t	local_policy;	/* local policies		*/
    SPF_c_results_t	exp;		/* explanation string		*/

    
    /*
     * synthesized from the above input values
     */
    char	*lp_from;		/* local part of env_from	*/
/*    char	*env_from;	*/
    char	*dp_from;		/* domain part of env_from	*/
    char	*cur_dom;		/* "current domain" per SPF spec*/
/*    struct in_addr *ip;	*/
/*    time_t	time;		*/	/* current time			*/
    char	*client_dom;		/* verified domain from client IP */
/*    char	*helo_dom;	*/
/*    char	*rec_dom;	*/

    size_t	max_var_len;		/* max strlen of above vars	*/
} SPF_iconfig_t;

#define SPF_EXP_MOD_NAME	"exp-text"



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


typedef struct 
{
    unsigned int	version:    3;	/* SPF spec version number	*/
    unsigned int	num_mech:   6;	/* number of mechanisms 	*/
    unsigned int	num_mod:    5;	/* number of modifiers		*/
    unsigned int	mech_len:   9;	/* bytes of compiled data	*/
    unsigned int	mod_len:    9;	/* bytes of compiled data	*/
} SPF_rec_header_t;


#define PREFIX_PASS	SPF_RESULT_PASS
#define PREFIX_FAIL	SPF_RESULT_FAIL
#define PREFIX_SOFTFAIL	SPF_RESULT_SOFTFAIL
#define PREFIX_NEUTRAL  SPF_RESULT_NEUTRAL
#define PREFIX_UNKNOWN	SPF_RESULT_UNKNOWN



/*
 * Mechanisms
 */

#define MECH_A		1
#define MECH_MX		2
#define MECH_PTR	3
#define MECH_INCLUDE	4
#define MECH_IP4	5
#define MECH_IP6	6
#define MECH_EXISTS	7
#define MECH_ALL	8  
#define MECH_REDIRECT	9


#  if defined( WORDS_BIGENDIAN )
struct SPF_mech_struct
{
    unsigned int	prefix_type: 3;
    unsigned int	mech_type:   4;
    unsigned int	parm_len:    9;	/* bytes of data or cidr len	*/
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  elif !defined( WORDS_BIGENDIAN )
struct SPF_mech_struct
{
    unsigned int	mech_type:   4;
    unsigned int	prefix_type: 3;
    unsigned int	parm_len:    9;	/* bytes of data or cidr len	*/
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
typedef struct SPF_mech_struct SPF_mech_t;
#define NETWORK_SIZEOF_MECH_T	2	/* network format		*/



/*
 * Modifiers
 */

typedef struct {
    unsigned char	name_len;
    unsigned char	data_len;
} SPF_mod_t;
#define NETWORK_SIZEOF_MOD_T	2	/* network format		*/



/*
 * Optional data to mech/mod
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


#  if defined( WORDS_BIGENDIAN )
struct SPF_data_str_struct
{
    unsigned int	parm_type:   4;
    unsigned int	reserved:    4;
    unsigned int	len:	     8;
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  elif !defined( WORDS_BIGENDIAN )
struct SPF_data_str_struct
{
    unsigned int	reserved:    4;
    unsigned int	parm_type:   4;
    unsigned int	len:	     8;
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
typedef struct SPF_data_str_struct SPF_data_str_t;
#define NETWORK_SIZEOF_DATA_STR_T 2	/* network format		*/


#  if defined( WORDS_BIGENDIAN )
struct SPF_data_var_struct
{
    unsigned int	parm_type:   4;
    unsigned int	num_rhs:     4;	/* chop subdomai name		*/
    unsigned int	rev:	     1;	/* reverse 			*/
    unsigned int	url_encode:  1;	/* do URL encoding		*/
    unsigned int	delim_dot:   1;	/* delimiter char: .		*/
    unsigned int	delim_dash:  1;	/* delimiter char: -		*/
    unsigned int	delim_plus:  1;	/* delimiter char: +		*/
    unsigned int	delim_equal: 1;	/* delimiter char: =		*/
    unsigned int	delim_bar:   1;	/* delimiter char: |		*/
    unsigned int	delim_under: 1;	/* delimiter char: _		*/
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  elif !defined( WORDS_BIGENDIAN )
struct SPF_data_var_struct
{
    unsigned int	num_rhs:     4;
    unsigned int	parm_type:   4;
    unsigned int	delim_under: 1;
    unsigned int	delim_bar:   1;
    unsigned int	delim_equal: 1;
    unsigned int	delim_plus:  1;
    unsigned int	delim_dash:  1;
    unsigned int	delim_dot:   1;
    unsigned int	url_encode:  1;
    unsigned int	rev:	     1;
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
typedef struct SPF_data_var_struct SPF_data_var_t;
#define NETWORK_SIZEOF_DATA_VAR_T 2	/* network format		*/


#  if defined( WORDS_BIGENDIAN )
struct SPF_data_cidr_struct
{
    unsigned int	parm_type:   4;
    unsigned int	ipv4:	     5;
    unsigned int	ipv6:	     7;
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  elif !defined( WORDS_BIGENDIAN )
struct SPF_data_cidr_struct
{
    unsigned int	ipv4:	     5;
    unsigned int	parm_type:   4;
    unsigned int	ipv6:	     7;
} __attribute__ ((packed));		/* FIXME: remove packed		*/
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
typedef struct SPF_data_cidr_struct  SPF_data_cidr_t;
#define NETWORK_SIZEOF_DATA_CIDR_T 2	/* network format		*/


typedef union
{
    SPF_data_var_t	dv;
    SPF_data_str_t	ds;
    SPF_data_cidr_t	dc;
} SPF_data_t;
#define NETWORK_SIZEOF_DATA_T	2	/* network format		*/



/*
 * Compiled SPF records as used internally by libspf2
 */

typedef struct
{
    SPF_rec_header_t	header;

    SPF_mech_t		*mech_first;	/* buffer for mechanisms	*/
    SPF_mech_t		*mech_last;
    size_t		mech_buf_len;	/* malloc'ed size		*/
    size_t		mech_len;	/* used size (non-network format) */

    SPF_mod_t		*mod_first;	/* buffer for modifiers		*/
    SPF_mod_t		*mod_last;
    size_t		mod_buf_len;	/* malloc'ed size		*/
    size_t		mod_len;	/* used size (non-network format) */
} SPF_internal_t;



/*
 * misc macros to make the code look cleaner than it really is
 */

#ifndef SPF_MAX_DNS_MECH
/* It is a bad idea to change this for two reasons.
 *
 * First, the obvious reason is the delays caused on the mail server
 * you are running.  DNS lookups that timeout can be *very* time
 * consuming, and even successful DNS lookups can take 200-500ms.
 * Many MTAs can't afford to wait long and even 2sec is pretty bad.
 *
 * The second, and more important reason, is the SPF records come from
 * a third party which may be malicious.  This third party can direct
 * DNS lookups to be sent to anyone.  If there isn't a limit, then it
 * is easy for someone to create a distributed denial of service
 * attack simply by sending a bunch of emails.  Unlike the delays on
 * your system caused by many DNS lookups, you might not even notice
 * that you are being used as part of a DDoS attack.
 */
#define SPF_MAX_DNS_MECH 10
#endif
#ifndef SPF_MAX_DNS_PTR
/* It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_PTR   5
#endif
#ifndef SPF_MAX_DNS_MX
/* It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_MX    5
#endif


static inline SPF_internal_t *SPF_id2spfi( SPF_id_t spfid ) 
    { return (SPF_internal_t *)spfid; }
static inline SPF_id_t SPF_spfi2id( SPF_internal_t *spfi ) 
    { return (SPF_id_t)spfi; }

static inline SPF_iconfig_t *SPF_cid2spfic( SPF_config_t spfcid ) 
    { return (SPF_iconfig_t *)spfcid; }
static inline SPF_config_t SPF_spfic2cid( SPF_iconfig_t *spfic ) 
    { return (SPF_config_t)spfic; }
  
/* FIXME: need to make these network/compiler portable	*/
static inline size_t SPF_mech_data_len( SPF_mech_t * mech )
    { return (mech->mech_type == MECH_IP4) ? sizeof( struct in_addr ) : (mech->mech_type == MECH_IP6) ? sizeof( struct in6_addr ) : mech->parm_len; }
static inline SPF_mech_t *SPF_next_mech( SPF_mech_t * mech )
    { return (SPF_mech_t *)( (char *)mech + sizeof(SPF_mech_t) + SPF_mech_data_len( mech ));}
static inline SPF_data_t *SPF_mech_data( SPF_mech_t *mech )
    { return (SPF_data_t *)( (char *)mech + sizeof(SPF_mech_t)); }
static inline SPF_data_t *SPF_mech_end_data( SPF_mech_t *mech )
    { return (SPF_data_t *)( (char *)SPF_next_mech(mech)); }
static inline struct in_addr *SPF_mech_ip4_data( SPF_mech_t *mech )
    { return (struct in_addr *)( (char *)mech + sizeof(SPF_mech_t)); }
static inline struct in6_addr *SPF_mech_ip6_data( SPF_mech_t *mech )
    { return (struct in6_addr *)( (char *)mech + sizeof(SPF_mech_t)); }

static inline SPF_data_t *SPF_next_data( SPF_data_t *data )
    { return (SPF_data_t *)( (char *)data + sizeof(SPF_data_t) + (data->ds.parm_type == PARM_STRING ? data->ds.len : 0)); }
static inline char *SPF_data_str( SPF_data_t *data )
    { return (char *)data + sizeof(SPF_data_t); }

static inline SPF_mod_t *SPF_next_mod( SPF_mod_t *mod )
    { return (SPF_mod_t *)( (char *)mod + sizeof(SPF_mod_t) + mod->name_len + mod->data_len); }
static inline char *SPF_mod_name( SPF_mod_t *mod )
    { return (char *)mod + sizeof(SPF_mod_t); }
static inline SPF_data_t *SPF_mod_data( SPF_mod_t *mod )
    { return (SPF_data_t *)((char *)mod + sizeof(SPF_mod_t) + mod->name_len); }
static inline SPF_data_t *SPF_mod_end_data( SPF_mod_t *mod )
    { return (SPF_data_t *)((char *)SPF_mod_data(mod) + mod->data_len); }


SPF_err_t SPF_expand( SPF_config_t spfcid, SPF_dns_config_t spfdc,
		SPF_data_t *data, size_t data_len,
		char **buf, size_t *buf_len);
SPF_err_t SPF_find_mod_data( SPF_config_t spfcid, SPF_id_t spfid, const char *mod_name,
		       SPF_data_t **data, size_t *data_len );

SPF_err_t SPF_data2str( char **p_p, char *p_end,
			SPF_data_t *data, SPF_data_t *data_end,
			int is_mech, int cidr_ok );


char *SPF_sanitize( SPF_config_t spfcid, char *str );
int SPF_is_loopback( SPF_config_t spfcid );

static inline unsigned int SPF_c2ui( char c ) {return (unsigned int)c;}

void SPF_print_sizeof(void);


SPF_err_t SPF_c_mech_add( SPF_id_t spfid, int mech_type, int prefix );
SPF_err_t SPF_c_mech_data_add( SPF_id_t spfid, char const **p_p, char const **p_token, int cidr_ok );
SPF_err_t SPF_c_mech_ip4_add( SPF_id_t spfid, char const **p_p, char const **p_token );
SPF_err_t SPF_c_mech_ip6_add( SPF_id_t spfid, char const **p_p, char const **p_token );
SPF_err_t SPF_c_mod_add( SPF_id_t spfid, const char *mod_name, size_t name_len );
SPF_err_t SPF_c_mod_data_add( SPF_id_t spfid, char const **p_p, char const **p_token, int cidr_ok );

int SPF_mech_cidr( SPF_config_t spfcid, SPF_mech_t *mech );
int SPF_ip_match( SPF_config_t spfcid, SPF_mech_t *mech,
		  struct in_addr ipv4 );
int SPF_ip_match6( SPF_config_t spfcid, SPF_mech_t *mech,
		   struct in6_addr ipv6 );



#endif
