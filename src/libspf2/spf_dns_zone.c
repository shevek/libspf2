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

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif


#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_zone.h"


/*
 * this is really little more than a proof-of-concept static zone.
 *
 * The static zone shouldn't just be an unsorted list that must be
 * completely searched each time.  Rather something should be done to
 * allow quicker access.  For example, sorting/bsearch, or red-black
 * trees, or perfect hashes, or something.
 *
 * Note that wildcards mean that a domain could match more than one
 * record.  The most specific record should match.
 *
 * Also, SPF records could be byte-compiled.
 */


typedef struct
{
    SPF_dns_rr_t	**zone;
    int			num_zone;
    int			zone_buf_len;
    SPF_dns_rr_t	nxdomain;
} SPF_dns_zone_config_t; 



static inline SPF_dns_zone_config_t *SPF_voidp2spfhook( void *hook ) 
    { return (SPF_dns_zone_config_t *)hook; }
static inline void *SPF_spfhook2voidp( SPF_dns_zone_config_t *spfhook ) 
    { return (void *)spfhook; }




static SPF_dns_rr_t *SPF_dns_find_zone( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_zone_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    int		i;

    if ( strncmp( domain, "*.", 2 ) == 0 )
    {
	for( i = 0; i < spfhook->num_zone; i++ )
	{
	    if ( spfhook->zone[i]->rr_type == rr_type
		 && strcmp( spfhook->zone[i]->domain, domain ) == 0 )
		return spfhook->zone[i];
	}
    } else {
	size_t	domain_len = strlen( domain );

	for( i = 0; i < spfhook->num_zone; i++ )
	{
	    if ( spfhook->zone[i]->rr_type != rr_type
		 && spfhook->zone[i]->rr_type != ns_t_any )
		continue;

	    if ( strncmp( spfhook->zone[i]->domain, "*.", 2 ) == 0 )
	    {
		size_t	zdomain_len = strlen( spfhook->zone[i]->domain ) - 2;

		if ( zdomain_len <= domain_len
		     && strcmp( spfhook->zone[i]->domain + 2,
				domain + (domain_len - zdomain_len) ) == 0 )
		    return spfhook->zone[i];
	    } else {
		if ( strcmp( spfhook->zone[i]->domain, domain ) == 0 )
		    return spfhook->zone[i];
	    }
	}
    }
    

    return NULL;
}



static SPF_dns_rr_t *SPF_dns_lookup_zone( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_zone_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    SPF_dns_rr_t *spfrr;

    spfrr = SPF_dns_find_zone( spfdcid, domain, rr_type );
    if ( spfrr )
	return spfrr;

    if ( spfdic->layer_below )
	return SPF_dcid2spfdic( spfdic->layer_below )->lookup( spfdic->layer_below, domain, rr_type, should_cache );
    else
	return &spfhook->nxdomain;
}


SPF_dns_rr_t *SPF_dns_zone_add_str( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, SPF_dns_stat_t herrno, const char *data )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_zone_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    SPF_dns_rr_t		*spfrr;

    int		err;
    int		cnt;


    /* try to find an existing record */
    spfrr = SPF_dns_find_zone( spfdcid, domain, rr_type );

    /* create a new record */
    if ( spfrr == NULL )
    {
	spfrr = SPF_dns_make_rr( spfdcid, domain, rr_type, 24*60*60, herrno );
	if ( spfrr == NULL )
	    return NULL;

	
	if ( spfhook->num_zone == spfhook->zone_buf_len )
	{
	    int			new_len;
	    SPF_dns_rr_t	**new_zone;
	    int			i;

	    
	    new_len = spfhook->zone_buf_len
		+ (spfhook->zone_buf_len >> 2) + 4;
	    new_zone = realloc( spfhook->zone,
				new_len * sizeof( *new_zone ) );
	    if ( new_zone == NULL )
		return NULL;

	    for( i = spfhook->zone_buf_len; i < new_len; i++ )
		new_zone[i] = NULL;

	    spfhook->zone_buf_len = new_len;
	    spfhook->zone = new_zone;
	}


	spfhook->zone[ spfhook->num_zone ] = spfrr;
	spfhook->num_zone++;

	if ( rr_type == ns_t_any )
	{
	    if ( data )
		SPF_error( "RR type ANY can not have data.");
	    if ( herrno == NETDB_SUCCESS )
		SPF_error( "RR type ANY must return a DNS error code.");
	}

	if ( herrno != NETDB_SUCCESS )
	    return spfrr;

    }
    
    
    /*
     * initialize stuff
     */
    cnt = spfrr->num_rr;
    
    switch( rr_type )
    {
    case ns_t_a:
	if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
				    sizeof( spfrr->rr[cnt]->a ) ) != SPF_E_SUCCESS )
	    return spfrr;

	err = inet_pton( AF_INET, data, &spfrr->rr[cnt]->a );
	if ( err <= 0 )
	    return NULL;
	break;
		
    case ns_t_aaaa:
	if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
				    sizeof( spfrr->rr[cnt]->aaaa ) ) != SPF_E_SUCCESS )
	    return spfrr;

	err = inet_pton( AF_INET6, data, &spfrr->rr[cnt]->aaaa );
	if ( err <= 0 )
	    return NULL;
	break;
		
    case ns_t_mx:
	if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
				    strlen( data ) + 1 ) != SPF_E_SUCCESS )
	    return spfrr;
	strcpy( spfrr->rr[cnt]->mx, data );
	break;
		
    case ns_t_txt:
	if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
				    strlen( data ) + 1 ) != SPF_E_SUCCESS )
	    return spfrr;
	strcpy( spfrr->rr[cnt]->txt, data );
	break;
		
    case ns_t_ptr:
	if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
				    strlen( data ) + 1 ) != SPF_E_SUCCESS )
	    return spfrr;
	strcpy( spfrr->rr[cnt]->ptr, data );
	break;
		
    case ns_t_any:
	if ( data )
	    SPF_error( "RR type ANY can not have data.");
	if ( herrno == NETDB_SUCCESS )
	    SPF_error( "RR type ANY must return a DNS error code.");
	SPF_error( "RR type ANY can not have multiple RR.");
	break;
		
    default:
	SPF_error( "Invalid RR type" );
	break;
    }		    

    spfrr->num_rr = cnt + 1;

    return spfrr;
}



SPF_dns_config_t SPF_dns_create_config_zone( SPF_dns_config_t layer_below, const char *name )
{
    SPF_dns_iconfig_t     *spfdic;
    SPF_dns_zone_config_t *spfhook;
    
    spfdic = malloc( sizeof( *spfdic ) );
    if ( spfdic == NULL )
	return NULL;

    spfdic->hook = malloc( sizeof( SPF_dns_zone_config_t ) );
    if ( spfdic->hook == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfdic->destroy      = SPF_dns_destroy_config_zone;
    spfdic->lookup       = SPF_dns_lookup_zone;
    spfdic->get_spf      = NULL;
    spfdic->get_exp      = NULL;
    spfdic->add_cache    = NULL;
    spfdic->layer_below  = layer_below;
    if ( name )
	spfdic->name     = name;
    else
	spfdic->name     = "zone";
    
    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->zone_buf_len = 32;
    spfhook->num_zone = 0;
    spfhook->zone = calloc( spfhook->zone_buf_len, sizeof( *spfhook->zone ) );

    if ( spfhook->zone == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfhook->nxdomain = SPF_dns_nxdomain;
    spfhook->nxdomain.source = SPF_spfdic2dcid( spfdic );

    return SPF_spfdic2dcid( spfdic );
}

void SPF_dns_reset_config_zone( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_zone_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    int				i;

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    if ( spfhook == NULL )
	SPF_error( "spfdcid.hook is NULL" );
	
    if ( spfhook->zone == NULL )
	SPF_error( "spfdcid.hook->zone is NULL" );
	
    for( i = 0; i < spfhook->zone_buf_len; i++ )
    {
	if ( spfhook->zone[i] )
	    SPF_dns_reset_rr( spfhook->zone[i] );
    }
}


void SPF_dns_destroy_config_zone( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_zone_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    int				i;

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    if ( spfhook )
    {
	for( i = 0; i < spfhook->zone_buf_len; i++ )
	{
	    if ( spfhook->zone[i] )
		SPF_dns_destroy_rr( spfhook->zone[i] );
	}

	if ( spfhook->zone ) free( spfhook->zone );
	free( spfhook );
    }
    
    free( spfdic );
}

