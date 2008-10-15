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




#ifndef INC_SPF_DNS_RR
#define INC_SPF_DNS_RR

#include "spf_dns.h"

/**
 * Data from a DNS RR.
 *
 * The strings in this union are usually  malloc'ed larger than the
 * size of the union.  Only create pointers to it!
 */
typedef
union
{
    struct in_addr	a;
    char			ptr[1];
    char			mx[1];
    char			txt[1];
    struct in6_addr	aaaa;
} SPF_dns_rr_data_t;

/**
 * A DNS packet.
 *
 * This structure does not semantically match the DNS packet
 * structure. It assumes that only one RR type was of interest,
 * and that all RRs in the packet are of that type.
 *
 * This is also used in spf_dns_zone.c
 */
typedef
struct SPF_dns_rr_struct
{
    /* query information */
    char				*domain;		/**< FQDN queried for.		*/
    size_t				 domain_buf_len;/**< Alloced size of domain.	*/

    ns_type				 rr_type;		/**< Type of RR queried for.	*/

    /* answer information */
    int					 num_rr;	/**< Number of RR returned in RR.	*/
    SPF_dns_rr_data_t	**rr;		/**< RR set returned.		*/
    size_t				*rr_buf_len;/**< Alloced size of each RR.	*/
    int					 rr_buf_num;/**< Number of RR allocated.	*/

    time_t				 ttl;		/**< Raw TTL.			*/
    time_t				 utc_ttl;	/**< TTL adjusted to UTC.		*/
    SPF_dns_stat_t		 herrno;	/**< h_error returned from query.	*/

    /* misc information */
    void				*hook;		/**< Used by DNS layers.		*/
    SPF_dns_server_t	*source;	/**< Which layer created this RR.  */
} SPF_dns_rr_t;

SPF_dns_rr_t	*SPF_dns_rr_new(void);
void			 SPF_dns_rr_free(SPF_dns_rr_t *spfrr);
SPF_dns_rr_t	*SPF_dns_rr_new_init(SPF_dns_server_t *spf_dns_server,
						const char *domain,
						ns_type rr_type, int ttl,
						SPF_dns_stat_t herrno);
SPF_dns_rr_t	*SPF_dns_rr_new_nxdomain(SPF_dns_server_t *spf_dns_server,
						const char *domain);

SPF_errcode_t	 SPF_dns_rr_buf_realloc(SPF_dns_rr_t *spfrr,
						int idx, size_t len );
SPF_errcode_t	 SPF_dns_rr_dup(SPF_dns_rr_t **dstp, SPF_dns_rr_t *src);


#endif
