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



#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_null.h"


typedef struct
{
    int		debug;
} SPF_dns_null_config_t; 


static inline SPF_dns_null_config_t *SPF_voidp2spfhook( void *hook ) 
    { return (SPF_dns_null_config_t *)hook; }
static inline void *SPF_spfhook2voidp( SPF_dns_null_config_t *spfhook ) 
    { return (void *)spfhook; }



static SPF_dns_rr_t *SPF_dns_lookup_null( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_null_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    SPF_dns_rr_t		*spfrr;
    const char			*source;

    if ( spfhook->debug )
	SPF_debugf( "DNS %s lookup:  %s  %s (%d)",
		 spfdic->name, domain,
		 ( (rr_type == ns_t_a)     ? "A" :
		   (rr_type == ns_t_aaaa)  ? "AAAA" :
		   (rr_type == ns_t_mx)    ? "MX" :
		   (rr_type == ns_t_txt)   ? "TXT" :
		   (rr_type == ns_t_ptr)   ? "PTR" :
		   (rr_type == ns_t_any)   ? "ANY" :
		   (rr_type == ns_t_invalid) ? "BAD" :
		   "??" ),
		 rr_type );

    if ( spfdic->layer_below )
	spfrr = SPF_dcid2spfdic( spfdic->layer_below )->lookup( spfdic->layer_below, domain, rr_type, should_cache );
	
    else
	spfrr = &SPF_dns_nxdomain;

    if ( spfhook->debug )
    {
	if ( spfrr->source )
	{
	    source = SPF_dcid2spfdic( spfrr->source )->name;
	    if ( source == NULL )
		source = "(null)";
	}
	else
	    source = "null";
	
	SPF_debugf( "DNS %s found:   %s  %s (%d)  TTL: %ld  RR found: %d  herrno: %d  source: %s",
		 spfdic->name, spfrr->domain,
		 ( (spfrr->rr_type == ns_t_a)     ? "A" :
		   (spfrr->rr_type == ns_t_aaaa)  ? "AAAA" :
		   (spfrr->rr_type == ns_t_mx)    ? "MX" :
		   (spfrr->rr_type == ns_t_txt)   ? "TXT" :
		   (spfrr->rr_type == ns_t_ptr)   ? "PTR" :
		   (spfrr->rr_type == ns_t_any)   ? "ANY" :
		   (spfrr->rr_type == ns_t_invalid) ? "BAD" :
		   "??" ),
		 spfrr->rr_type, spfrr->ttl, spfrr->num_rr, spfrr->herrno,
		 source );
    }
    
    return spfrr;
}


SPF_dns_config_t SPF_dns_create_config_null( SPF_dns_config_t layer_below, int debug, const char *name )
{
    SPF_dns_iconfig_t     *spfdic;
    SPF_dns_null_config_t *spfhook;
    
    spfdic = malloc( sizeof( *spfdic ) );
    if ( spfdic == NULL )
	return NULL;

    spfdic->hook = malloc( sizeof( SPF_dns_null_config_t ) );
    if ( spfdic->hook == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfdic->destroy      = SPF_dns_destroy_config_null;
    spfdic->lookup       = SPF_dns_lookup_null;
    spfdic->get_spf      = NULL;
    spfdic->get_exp      = NULL;
    spfdic->add_cache    = NULL;
    spfdic->layer_below  = layer_below;
    if ( name )
	spfdic->name     = name;
    else
	spfdic->name     = "null";
    
    spfhook = SPF_voidp2spfhook( spfdic->hook );
    spfhook->debug = debug;

    return SPF_spfdic2dcid( spfdic );
}

void SPF_dns_reset_config_null( SPF_dns_config_t spfdcid )
{
    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );
}

void SPF_dns_destroy_config_null( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    SPF_dns_reset_config_null( spfdcid );

    if ( spfdic->hook )
	free( spfdic->hook );
    if ( spfdic )
	free( spfdic );
}
