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




#ifndef INC_SPF_DNS_INTERNAL
#define INC_SPF_DNS_INTERNAL



/* The strings in this union are usually  malloc'ed larger than the
 * size of the union.  Only create pointers to it! */
typedef union
{
    struct in_addr	a;
    char		ptr[1];
    char		mx[1];
    char		txt[1];
    struct in6_addr	aaaa;
} SPF_dns_rr_data_t;
    

typedef struct
{
    /* query information */
    char		*domain;	/* FQDN queried for		*/
    size_t		domain_buf_len;	/* alloced size of domain	*/

    ns_type		rr_type;	/* type of RR queried for	*/


    /* answer information */
    int			num_rr;		/* number of RR returned in rr	*/
    SPF_dns_rr_data_t	**rr;		/* rr set returned		*/
    size_t		*rr_buf_len;	/* alloced size of each rr	*/
    int			rr_buf_num;	/* number of RR allocated	*/

    time_t		ttl;		/* raw TTL			*/
    time_t		utc_ttl;	/* TTL adjusted to UTC		*/
    SPF_dns_stat_t	herrno;		/* h_error returned from query	*/

    /* misc information */
    void		*hook;		/* used by DNS layers		*/
    SPF_dns_config_t	source;		/* which layer created this RR  */
} SPF_dns_rr_t;




/*
 * You do not need to free RR info that have been returned by the lookup
 * functions, just ones that you create or dup
 */
SPF_dns_rr_t *SPF_dns_make_rr( SPF_dns_config_t spfdcid, const char *domain,
			       ns_type rr_type, int ttl,
			       SPF_dns_stat_t herrno );
SPF_dns_rr_t *SPF_dns_create_rr( void );
void SPF_dns_reset_rr( SPF_dns_rr_t *spfrr );
SPF_err_t SPF_dns_rr_buf_malloc( SPF_dns_rr_t *dst, int i, size_t len );
SPF_err_t SPF_dns_copy_rr( SPF_dns_rr_t *dst, SPF_dns_rr_t *src );
SPF_dns_rr_t *SPF_dns_dup_rr( SPF_dns_rr_t *orig );
void SPF_dns_destroy_rr_var( SPF_dns_rr_t *spfrr );
void SPF_dns_destroy_rr( SPF_dns_rr_t *spfrr );


/*
 * These lookup functions just return pointers to an internal structure.
 * The pointers become invalid as soon as the next lookup function is
 * called because the structure may be reused.
 *
 * If you need to know about more than one RR at a time, you can duplicate
 * the entry and then free it when you are done.  
 */

SPF_dns_rr_t *SPF_dns_lookup( SPF_dns_config_t spfdcid,
			      const char *domain, ns_type rr_type,
			      int should_cache );
SPF_dns_rr_t *SPF_dns_rlookup( SPF_dns_config_t spfdcid,
			       struct in_addr ipv4, ns_type rr_type,
			       int should_cache );
SPF_dns_rr_t *SPF_dns_rlookup6( SPF_dns_config_t spfdcid,
				struct in6_addr ipv6, ns_type rr_type,
				int should_cache );



typedef void (*SPF_dns_destroy_t)( SPF_dns_config_t spfdcid );
typedef SPF_dns_rr_t *(*SPF_dns_lookup_t)( SPF_dns_config_t spfdcid,
					   const char *domain,
					   ns_type ns_type, int should_cache );

typedef SPF_err_t (*SPF_dns_get_spf_t)( SPF_config_t spfcid,
					SPF_dns_config_t spfdcid,
					const char *domain,
					SPF_c_results_t *c_results );
typedef SPF_err_t (*SPF_dns_get_exp_t)( SPF_config_t spfcid, 
					SPF_dns_config_t spfdcid,
					const char *domain,
					char **buf, size_t *buf_len );
typedef int (*SPF_dns_add_cache_t)( SPF_config_t spfcid, 
				    SPF_dns_config_t spfdcid,
				    SPF_dns_rr_t spfrr );



typedef struct SPF_dns_iconfig_struct
{
    SPF_dns_destroy_t	destroy;

    SPF_dns_lookup_t	lookup;
    SPF_dns_get_spf_t	get_spf;
    SPF_dns_get_exp_t	get_exp;
    SPF_dns_add_cache_t add_cache;

    /* the next DNS layer down to call if this layer can't give an answer */
    SPF_dns_config_t	layer_below;

    const char		*name;		/* name of the layer		*/
    void		*hook;
} SPF_dns_iconfig_t;


static inline SPF_dns_iconfig_t *SPF_dcid2spfdic( SPF_dns_config_t spfdcid ) 
    { return (SPF_dns_iconfig_t *)spfdcid; }
static inline SPF_dns_config_t SPF_spfdic2dcid( SPF_dns_iconfig_t *spfdic ) 
    { return (SPF_dns_config_t)spfdic; }


extern SPF_dns_rr_t SPF_dns_nxdomain;


#endif
