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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif



#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"


SPF_err_t SPF_get_spf( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
			   const char *domain, SPF_c_results_t *c_results )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic( spfcid );
    SPF_dns_iconfig_t	*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_rr_t	*rr_txt;
    
    int		i;
    SPF_err_t	err;
    int		num_found;
    

    if ( spfcid == NULL )
	SPF_error( "spfcid is null" );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is null" );

    if ( domain == NULL )
    {
	domain = spfic->cur_dom;
	if ( domain == NULL )
	    domain = spfic->helo_dom;
    
	if ( domain == NULL )
	    return SPF_E_NOT_CONFIG;
    }
    
    SPF_free_c_results( c_results );

    if ( spfdic->get_spf )
	return spfdic->get_spf( spfcid, spfdcid, domain, c_results );

    rr_txt = SPF_dns_lookup( spfdcid, domain, ns_t_txt, TRUE );

    switch( rr_txt->herrno )
    {
    case HOST_NOT_FOUND:
      /*
  	c_results->err = SPF_E_NOT_HOST;
	return SPF_E_NOT_HOST;
	break;
      */
    
    case NO_DATA:
	c_results->err = SPF_E_NOT_SPF;
	return SPF_E_NOT_SPF;
	break;

    case TRY_AGAIN:
	c_results->err = SPF_E_DNS_ERROR;
	return SPF_E_DNS_ERROR;
	break;

    case NETDB_SUCCESS:
	break;

    default:
	c_results->err = SPF_E_DNS_ERROR;
	return SPF_E_DNS_ERROR;
	break;
    }
	    
    if ( rr_txt->num_rr == 0 )
    {
	SPF_warning( "No TXT records returned from DNS lookup" );
	
	c_results->err = SPF_E_NOT_SPF;
	return SPF_E_NOT_SPF;
    }
    
    /* check for multiple SPF records */
    num_found = 0;
    for( i = 0; i < rr_txt->num_rr; i++ )
    {
	if ( strncmp( rr_txt->rr[i]->txt,
		      SPF_VER_STR " ", sizeof( SPF_VER_STR " " ) - 1) == 0 )
	{
	    if ( spfic->debug > 0 )
		SPF_debugf( "found SPF record: %s", rr_txt->rr[i]->txt );
	    
	    num_found++;
	}
    }
    if ( num_found == 0 )
	return SPF_E_NOT_SPF;
    if ( num_found > 1 )
	return SPF_E_RESULT_UNKNOWN;
    
    /* try to compile the SPF record */
    err = SPF_E_NOT_SPF;
    for( i = 0; i < rr_txt->num_rr; i++ )
    {
	err = SPF_compile( spfcid, rr_txt->rr[i]->txt, c_results );

	if ( err == SPF_E_SUCCESS )	/* FIXME:  support multiple versions */
	    break;
    }

    return err;
}
