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

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif


#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"


/*
 * helper functions
 */

void SPF_dns_destroy_config( SPF_dns_config_t spfdcid )
{
    SPF_dcid2spfdic( spfdcid )->destroy( spfdcid );
}

SPF_dns_rr_t *SPF_dns_lookup( SPF_dns_config_t spfdcid,
			      const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_rr_t *spfrr;
    
    spfrr = SPF_dcid2spfdic( spfdcid )->lookup( spfdcid, domain, rr_type, should_cache );

    if ( spfrr == NULL )
	SPF_error( "SPF DNS layer return NULL during a lookup." );
    return spfrr;
}

SPF_dns_rr_t *SPF_dns_rlookup( SPF_dns_config_t spfdcid,
			       struct in_addr ipv4, ns_type rr_type, int should_cache )
{

    union
    {
	struct in_addr	ipv4;
	unsigned char	x[4];
    } tmp;

    char	domain[ sizeof( "111.222.333.444.in-addr.arpa" ) ];
    SPF_dns_rr_t *spfrr;
    
    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    /*
     * make sure the scratch buffer is big enough
     */
    tmp.ipv4 = ipv4;

    snprintf( domain, sizeof( domain ), "%d.%d.%d.%d.in-addr.arpa",
	     tmp.x[3], tmp.x[2], tmp.x[1], tmp.x[0] );


    spfrr = SPF_dcid2spfdic( spfdcid )->lookup( spfdcid, domain, rr_type, should_cache );

    if ( spfrr == NULL )
	SPF_error( "SPF DNS layer return NULL during a rlookup." );
    return spfrr;
}


SPF_dns_rr_t *SPF_dns_rlookup6( SPF_dns_config_t spfdcid,
				struct in6_addr ipv6, ns_type rr_type, int should_cache )
{
    char	domain[ sizeof( struct in6_addr ) * 4 + sizeof( ".ip6.arpa" ) + 1 ];  /* nibbles */
    char	*p, *p_end;
    int		i;
    SPF_dns_rr_t *spfrr;

    
    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    p = domain;
    p_end = p + sizeof( domain );
			
    for( i = sizeof( struct in6_addr ) - 1; i >= 0; i-- )
    {
	p += snprintf( p, p_end - p, "%.1x.%.1x.",
		       ipv6.s6_addr[i] & 0xf,
		       ipv6.s6_addr[i] >> 4 );
    }

    /* squash the final '.' */
    p += snprintf( p, p_end - p, "ip6.arpa" );

    spfrr = SPF_dcid2spfdic( spfdcid )->lookup( spfdcid, domain, rr_type, should_cache );

    if ( spfrr == NULL )
	SPF_error( "SPF DNS layer return NULL during a rlookup6." );
    return spfrr;
}



SPF_dns_rr_t *SPF_dns_make_rr( SPF_dns_config_t spfdcid, const char *domain,
			       ns_type rr_type, int ttl,
			       SPF_dns_stat_t herrno )
{
    SPF_dns_rr_t	*spfrr;

    spfrr = SPF_dns_create_rr();
    if ( spfrr == NULL )
	return spfrr;

    spfrr->source = spfdcid;
    if ( domain )
    {
	spfrr->domain = strdup( domain );
	if ( spfrr == NULL )
	{
	    free( spfrr );
	    return NULL;
	}
	spfrr->domain_buf_len = strlen( domain ) + 1;
    } else {
	spfrr->domain = NULL;
	spfrr->domain_buf_len = 0;
    }
    spfrr->rr_type = rr_type;
    spfrr->ttl = ttl;
    spfrr->herrno = herrno;

    return spfrr;
}


SPF_dns_rr_t *SPF_dns_create_rr()
{
    SPF_dns_rr_t	*spfrr;

    spfrr = calloc( 1, sizeof( *spfrr ) );
    if ( spfrr == NULL )
	return spfrr;

    SPF_dns_reset_rr( spfrr );
    return spfrr;
}


void SPF_dns_reset_rr( SPF_dns_rr_t *spfrr )
{
    if ( spfrr == NULL )
	return;
    
    if ( spfrr->domain )
	spfrr->domain[0] = '\0';
    spfrr->rr_type = ns_t_invalid;
    spfrr->num_rr = 0;
    spfrr->ttl = 0;
    spfrr->utc_ttl = 0;
    spfrr->herrno = HOST_NOT_FOUND;
}


SPF_err_t SPF_dns_rr_buf_malloc( SPF_dns_rr_t *dst, int i, size_t len )
{
    if ( dst->rr_buf_num <= i )
    {
	SPF_dns_rr_data_t **new_data;
	size_t	*new_buf_len;
	int	new_num;
	int	j;
	
	/* allocate lots so we don't have to remalloc often */
	new_num = dst->rr_buf_num + (i + (i >> 2) + 4 );

	new_data = realloc( dst->rr, new_num * sizeof( *new_data ) );
	if ( new_data == NULL )
	    return SPF_E_NO_MEMORY;
	dst->rr = new_data;
	
	new_buf_len = realloc( dst->rr_buf_len,
			       new_num * sizeof( *new_buf_len ) );
	if ( new_buf_len == NULL )
	    return SPF_E_NO_MEMORY;
	dst->rr_buf_len = new_buf_len;
	
	for( j = dst->rr_buf_num; j < new_num; j++ )
	{
	    dst->rr[j] = NULL;
	    dst->rr_buf_len[j] = 0;
	}

	dst->rr_buf_num = new_num;
    }
    
    if ( dst->rr_buf_len[i] >= len )
	return SPF_E_SUCCESS;

    dst->rr_buf_len[i] = len;
    if ( dst->rr_buf_len[i] < sizeof( *dst->rr[i] ) )
	dst->rr_buf_len[i] = sizeof( *dst->rr[i] );
    dst->rr[i] = realloc( dst->rr[i], dst->rr_buf_len[i] );
    if ( dst->rr[i] == NULL )
	return SPF_E_NO_MEMORY;

    return SPF_E_SUCCESS;
}



SPF_err_t SPF_dns_copy_rr( SPF_dns_rr_t *dst, SPF_dns_rr_t *src )
{
    int		i;
    SPF_err_t	err;
    

    if ( src == NULL )
	SPF_error( "src is NULL" );

    if ( dst == NULL )
	SPF_error( "dst is NULL" );



    if ( src->domain && src->domain[0] != '\0' )
    {
	char   *new_domain;
	size_t new_len = strlen( src->domain ) + 1;

	if ( dst->domain_buf_len < new_len )
	{
	    new_domain = realloc( dst->domain, new_len );
	    if ( new_domain == NULL )
		return SPF_E_NO_MEMORY;

	    dst->domain = new_domain;
	    dst->domain_buf_len = new_len;
	}
	strcpy( dst->domain, src->domain );
    }
    else if ( dst->domain )
	dst->domain[0] = '\0';


    dst->rr_type = src->rr_type;
    dst->ttl     = src->ttl;
    dst->utc_ttl = src->utc_ttl;
    dst->herrno  = src->herrno;
    dst->source  = src->source;
    dst->num_rr  = src->num_rr;
    
    for( i = dst->num_rr - 1; i >= 0; i-- )
    {
	switch( dst->rr_type )
	{
	case ns_t_a:
	    err = SPF_dns_rr_buf_malloc( dst, i, sizeof( *dst->rr[i] ) );
	    if ( err )
		return err;
	    dst->rr[i]->a = src->rr[i]->a;
	    break;
		
	case ns_t_ptr:
	    err = SPF_dns_rr_buf_malloc( dst, i,
					 strlen( src->rr[i]->ptr ) + 1 );
	    if ( err )
		return err;
	    strcpy( dst->rr[i]->ptr, src->rr[i]->ptr );
	    break;
		
	case ns_t_mx:
	    err = SPF_dns_rr_buf_malloc( dst, i,
					 strlen( src->rr[i]->mx ) + 1 );
	    if ( err )
		return err;
	    strcpy( dst->rr[i]->mx, src->rr[i]->mx );
	    break;
		
	case ns_t_txt:
	    err = SPF_dns_rr_buf_malloc( dst, i,
					 strlen( src->rr[i]->txt ) + 1 );
	    if ( err )
		return err;
	    strcpy( dst->rr[i]->txt, src->rr[i]->txt );
	    break;
		
	case ns_t_aaaa:
	    err = SPF_dns_rr_buf_malloc( dst, i, sizeof( *dst->rr[i] ) );
	    if ( err )
		return err;
	    dst->rr[i]->aaaa = src->rr[i]->aaaa;
	    break;
		
	default:
	    break;
	}
    }

    return SPF_E_SUCCESS;
}


SPF_dns_rr_t *SPF_dns_dup_rr( SPF_dns_rr_t *orig )
{
    SPF_err_t		err;
    SPF_dns_rr_t	*spfrr;
    

    if ( orig == NULL )
	return NULL;

    spfrr = SPF_dns_create_rr();
    if ( spfrr == NULL )
	return NULL;

    err = SPF_dns_copy_rr( spfrr, orig );
    if ( err )
    {
	SPF_dns_destroy_rr( spfrr );
	return NULL;
    }

    return spfrr;
}


void SPF_dns_destroy_rr_var( SPF_dns_rr_t *spfrr )
{
    int			i;


    SPF_dns_reset_rr( spfrr );

    if ( spfrr->domain ) free( spfrr->domain );

    if ( spfrr->rr )
    {
	for( i = 0; i < spfrr->rr_buf_num; i++ )
	    if ( spfrr->rr[i] ) free( spfrr->rr[i] );

	free( spfrr->rr );
    }

    if ( spfrr->rr_buf_len ) free( spfrr->rr_buf_len );

    if ( spfrr->hook )
	free( spfrr->hook );
}


void SPF_dns_destroy_rr( SPF_dns_rr_t *spfrr )
{
    SPF_dns_destroy_rr_var( spfrr );

    free( spfrr );
}



/*
 * Set the SMPT client domain name
 */

void SPF_set_client_dom( SPF_config_t spfcid, SPF_dns_config_t spfdcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    SPF_dns_rr_t *rr_ptr;
    SPF_dns_rr_t *rr_a;
    SPF_dns_rr_t *rr_aaaa;
    
    int		i, j;
    
    int		max_ptr;


    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );


    if ( spfic->client_dom )
	return;
    
/*
 * The "p" macro expands to the validated domain name of the SMTP
 * client.  The validation procedure is described in section 5.4.  If
 * there are no validated domain names, the word "unknown" is
 * substituted.  If multiple validated domain names exist, the first one
 * returned in the PTR result is chosen.
 *
 *
 *   sending-host_names := ptr_lookup(sending-host_IP);
 *   for each name in (sending-host_names) {
 *     IP_addresses := a_lookup(name);
 *     if the sending-host_IP is one of the IP_addresses {
 *       validated_sending-host_names += name;
 *   } }
 */

    if ( spfic->client_ver == AF_INET )
    {
	rr_ptr = SPF_dns_dup_rr( SPF_dns_rlookup( spfdcid, spfic->ipv4, ns_t_ptr, FALSE ) );
    
	max_ptr = rr_ptr->num_rr;
	if ( max_ptr > spfic->max_dns_ptr )
	    max_ptr = spfic->max_dns_ptr;
	if ( max_ptr > SPF_MAX_DNS_PTR )
	    max_ptr = SPF_MAX_DNS_PTR;

	for( i = 0; i < max_ptr; i++ )
	{
	    rr_a = SPF_dns_lookup( spfdcid, rr_ptr->rr[i]->ptr, ns_t_a, FALSE );

	    for( j = 0; j < rr_a->num_rr; j++ )
	    {
		if ( rr_a->rr[j]->a.s_addr == spfic->ipv4.s_addr )
		{
		    spfic->client_dom = strdup( rr_ptr->rr[i]->ptr );
		    SPF_dns_destroy_rr( rr_ptr );
		    return;
		}
	    }
	}
	SPF_dns_destroy_rr( rr_ptr );
    }
	    
    else if ( spfic->client_ver == AF_INET6 )
    {
	rr_ptr = SPF_dns_dup_rr( SPF_dns_rlookup6( spfdcid, spfic->ipv6, ns_t_ptr, FALSE ) );

	max_ptr = rr_ptr->num_rr;
	if ( max_ptr > spfic->max_dns_ptr )
	    max_ptr = spfic->max_dns_ptr;
	if ( max_ptr > SPF_MAX_DNS_PTR )
	    max_ptr = SPF_MAX_DNS_PTR;

	for( i = 0; i < max_ptr; i++ )
	{
	    rr_aaaa = SPF_dns_lookup( spfdcid, rr_ptr->rr[i]->ptr, ns_t_aaaa, FALSE );

	    for( j = 0; j < rr_aaaa->num_rr; j++ )
	    {
		if ( memcmp( &rr_aaaa->rr[j]->aaaa, &spfic->ipv6,
			     sizeof( spfic->ipv6 ) ) == 0 )
		{
		    spfic->client_dom = strdup( rr_ptr->rr[i]->ptr );
		    SPF_dns_destroy_rr( rr_ptr );
		    return;
		}
	    }
	}
	SPF_dns_destroy_rr( rr_ptr );
    }

    spfic->client_dom = strdup( "unknown" );
}



SPF_dns_rr_t SPF_dns_nxdomain = 
{(char *)"", 0, ns_t_any, 0, NULL, NULL,  0, 0, 0, HOST_NOT_FOUND, NULL, NULL };
