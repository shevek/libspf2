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
# include <stdlib.h>       /* malloc / free */
# include <stdio.h>        /* stdin / stdout */
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"





SPF_err_t SPF_get_exp( SPF_config_t spfcid, SPF_id_t spfid,
		       SPF_dns_config_t spfdcid,
		       char **buf, size_t *buf_len )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic( spfcid );
    SPF_dns_iconfig_t	*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_rr_t	*rr_txt;
    SPF_c_results_t	c_results;
    
    char	*domain;
    SPF_err_t	err, ret_err;
    
    char	*exp_buf = NULL;
    size_t	exp_buf_len = 0;
    

    /*
     * There are lots of places to look for the explanation message,
     * some require DNS lookups, some don't.
     */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    if ( buf == NULL )
	SPF_error( "buf is NULL" );
    
    if ( buf_len == NULL )
	SPF_error( "buf_len is NULL" );


    domain = spfic->cur_dom;
    if ( domain == NULL )
	domain = spfic->helo_dom;
    
    if ( domain == NULL )
	return SPF_E_NOT_CONFIG;
    
    /*
     * start looking...  check spfid for exp-text=
     */

    err = SPF_find_mod_value( spfcid, spfid, spfdcid, SPF_EXP_MOD_NAME,
			      buf, buf_len );
    if ( err == SPF_E_SUCCESS )
	return err;
    

    /*
     * still looking...  check the spfid for exp=
     */

    err = SPF_find_mod_value( spfcid, spfid, spfdcid, "exp",
			      &exp_buf, &exp_buf_len );
    if ( err != SPF_E_SUCCESS )
    {
	/*
	 * still looking...  try to return default exp from spfcid
	 */
	if ( exp_buf ) free( exp_buf );

	err = SPF_E_SUCCESS;
	goto return_default;
    } 

    if ( exp_buf == NULL  ||  exp_buf[0] == '\0' )
    {
	/*
	 * still looking...  try to return default exp from spfcid
	 */
	if ( exp_buf ) free( exp_buf );

	err = SPF_E_MISSING_OPT;
	goto return_default;
    } 


    /*
     * still looking...  try doing a DNS lookup on the exp= name
     */

    if ( spfdic->get_exp )
    {
	err = spfdic->get_exp( spfcid, spfdcid, exp_buf, buf, buf_len );

	free( exp_buf );
	return err;
    }
    

    rr_txt = SPF_dns_lookup( spfdcid, exp_buf, ns_t_txt, TRUE );

    free( exp_buf );
    
    switch( rr_txt->herrno )
    {
    case HOST_NOT_FOUND:
    case NO_DATA:
	err = SPF_E_INVALID_OPT;
	goto return_default;
	break;

    case TRY_AGAIN:
	err = SPF_E_DNS_ERROR;
	goto return_default;
	break;

    case NETDB_SUCCESS:
	break;

    default:
	SPF_warning( "unknown DNS lookup error code" );
	err = SPF_E_DNS_ERROR;
	goto return_default;
	break;
    }
	    
    if ( rr_txt->num_rr == 0 )
    {
	SPF_warning( "No TXT records returned from DNS lookup" );
	
	err = SPF_E_INVALID_OPT;
	goto return_default;
    }
    

    /*
     * still looking...  try compiling this TXT record
     */

    /* FIXME  we are supposed to concatenate the TXT records */

    SPF_init_c_results( &c_results );
    err = SPF_compile_exp( spfcid, rr_txt->rr[0]->txt, &c_results );

    if ( err != SPF_E_SUCCESS )
    {
	/*
	 * still looking...  try to return default exp from spfcid
	 */

	if ( err && spfic->debug > 0 )
	    SPF_warning( c_results.err_msg );

	SPF_free_c_results( &c_results );

	goto return_default;
    }
    
    err = SPF_find_mod_value( spfcid, c_results.spfid, spfdcid,
			      SPF_EXP_MOD_NAME,
			      buf, buf_len );
    
    SPF_free_c_results( &c_results );
    
    if( err != SPF_E_SUCCESS )
	goto return_default;
    return err;


  return_default:

    ret_err = err;

    if ( *buf == NULL || *buf_len < SPF_C_ERR_MSG_SIZE )
    {
	char *new_err_msg;
		
	new_err_msg = realloc( *buf, SPF_C_ERR_MSG_SIZE );
	if ( new_err_msg == NULL )
	    return SPF_E_NO_MEMORY;

	*buf = new_err_msg;
	*buf_len = SPF_C_ERR_MSG_SIZE;
    }

    if ( spfic->exp.spfid == NULL )
    {
	/* give up looking */
	if( *buf )
	    snprintf( *buf, *buf_len, "SPF failure:  %s",
		      SPF_strerror( SPF_E_UNINIT_VAR ) );
	return SPF_E_UNINIT_VAR;
    }

    err = SPF_find_mod_value( spfcid, spfic->exp.spfid, spfdcid,
			      SPF_EXP_MOD_NAME,
			      buf, buf_len );

    if ( err && spfic->debug > 0 )
	SPF_warning( SPF_strerror( err ) );

    if( err != SPF_E_SUCCESS && *buf )
	snprintf( *buf, *buf_len, "SPF failure:  %s", SPF_strerror( err ) );

    return ret_err;
}

