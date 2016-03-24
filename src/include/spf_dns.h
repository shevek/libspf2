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




#ifndef INC_SPF_DNS
#define INC_SPF_DNS


/**
 * @file
 *
 * This library has the ability to use one or more of any of a number
 * of DNS "layers" to obtain DNS information.  These layers all have
 * compatible APIs, with only minor differences that relate to their
 * specific functions.  So, they can be mixed and matched in any order
 * to do what you want.
 *
 * When you create a new DNS layer, you can (optionally) specify the
 * layer below it.  If the current DNS layer is not able to resolve
 * the query, it will automatically call the lower layer.
 *
 * Some of the DNS layers allow for debugging information to be
 * printed, some do caching, and, of course, some return actual DNS
 * results either by query the network or by looking up the query in a
 * database.
 *
 * For details about each DNS layer, see the appropriate
 * spf_dns_<layer>.h include file.
 *
 *
 * For example, there is a caching DNS layer that saves the compiled
 * SPF records for future use.  While it takes a small amount of time
 * to compile the AOL SPF record, you will more than make up for it by
 * not having to parse the record every time you get a message from
 * AOL.
 * 
 * If you wanted to, you can even run the SPF system without using
 * real DNS lookups at all.  For testing, I used a DNS layer that
 * contained a built-in zone file.  This idea could easily be extended
 * to being able to read the zone file from disk, or to use a database
 * to access information.
 * 
 * One example of what you could do with such a zone file would be to
 * create your own SPF records for the many free-email providers.
 * Depending on whether you layer this local zone file before or after
 * the real DNS lookups, you can either override published SPF
 * records, or you can provide defaults until SPF records are
 * published.
 * 
 */


/*
 * For those who don't have <arpa/nameserv.h>
 */

/* XXX This should use a more sensible define. */
#if !defined( HAVE_NS_TYPE )

#define	ns_t_invalid	0
#define	ns_t_a		1
#define	ns_t_ns		2
#define	ns_t_cname	5
#define	ns_t_ptr	12
#define	ns_t_mx		15
#define	ns_t_txt	16
#define ns_t_aaaa	28
/* #define ns_t_a6		38 */
#define	ns_t_any        255		/**< Wildcard match. */

typedef int	ns_type;
#endif

#if ! HAVE_DECL_NS_T_INVALID
#define	ns_t_invalid	0
#endif


/*
 * For those who don't have <netdb.h>
 */

#if !defined(HAVE_NETDB_H) && !defined(_WIN32)
#define NETDB_SUCCESS	0
#define	HOST_NOT_FOUND 	1		/**< NXDOMAIN (authoritative answer)*/
#define	TRY_AGAIN		2		/**< SERVFAIL (no authoritative answer)*/
#define	NO_RECOVERY		3		/**< invalid/unimplmeneted query	*/
#define	NO_DATA			4		/**< host found, but no RR of req type*/
#endif
typedef int SPF_dns_stat_t;

typedef struct SPF_dns_server_struct SPF_dns_server_t;

#include "spf_request.h"
#include "spf_dns_rr.h"

/*
 * bundle up the info needed to use a dns method
 */

typedef void (*SPF_dns_destroy_t)(SPF_dns_server_t *spf_dns_server);
typedef SPF_dns_rr_t *(*SPF_dns_lookup_t)(
				SPF_dns_server_t *spf_dns_server,
				const char *domain,
				ns_type ns_type, int should_cache
					);
typedef SPF_errcode_t (*SPF_dns_get_spf_t)( SPF_server_t *spf_server,
					SPF_request_t *spf_request,
					SPF_response_t *spf_response,
					SPF_record_t **spf_recordp);
typedef SPF_errcode_t (*SPF_dns_get_exp_t)( SPF_server_t *spf_server,
					const char *domain,
					char **buf, size_t *buf_len );
typedef int (*SPF_dns_add_cache_t)( SPF_server_t *spf_server,
				    SPF_dns_rr_t spfrr );

struct SPF_dns_server_struct
{
	/** The destructor for this SPF_dns_server_t. If this is NULL, then
	 * the structure is assumed to be shared between multiple SPF_server_t
	 * objects, and is not freed when the server is destroyed, or by any call
	 * to SPF_dns_free(). In this case, it is assumed that somebody else knows,
	 * and will free the resolver at the appropriate object. */
    SPF_dns_destroy_t	 destroy;

    SPF_dns_lookup_t	 lookup;
    SPF_dns_get_spf_t	 get_spf;
    SPF_dns_get_exp_t	 get_exp;
    SPF_dns_add_cache_t  add_cache;

    /* the next DNS layer down to call if this layer can't give an answer */
    SPF_dns_server_t	*layer_below;

    const char			*name;		/* name of the layer		*/
	int					 debug;
    void				*hook;		/* server-specific data */
};


void			 SPF_dns_free( SPF_dns_server_t *spf_dns_server );
SPF_dns_rr_t	*SPF_dns_lookup( SPF_dns_server_t *spf_dns_server,
			      const char *domain, ns_type rr_type,
			      int should_cache );
SPF_dns_rr_t	*SPF_dns_rlookup( SPF_dns_server_t *spf_dns_server,
			       struct in_addr ipv4, ns_type rr_type,
			       int should_cache );
SPF_dns_rr_t	*SPF_dns_rlookup6( SPF_dns_server_t *spf_dns_server,
				struct in6_addr ipv6, ns_type rr_type,
				int should_cache );


/**
 * The client domain is the validated domain name of the client IP
 * address.  This is not just the domain name(s) found in the reverse
 * DNS tree, but involves checking to make sure these name(s) use the
 * client IP address.  The complete validation procedure is described
 * in section 5.4 of the SPF spec.
 */
char		*SPF_dns_get_client_dom(SPF_dns_server_t *spf_dns_server,
				SPF_request_t *sr);


#endif
