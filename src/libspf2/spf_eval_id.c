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


int SPF_mech_cidr( SPF_config_t spfcid, SPF_mech_t *mech )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_data_t		*data;
    
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );
    
    if ( mech == NULL )
	SPF_error( "mech is NULL" );
    
    switch( mech->mech_type )
    {
    case MECH_IP4:
    case MECH_IP6:
	return mech->parm_len;
	break;

    case MECH_A:
    case MECH_MX:
	data = SPF_mech_data( mech );
	if ( data <= SPF_mech_end_data( mech )
	     && data->dc.parm_type == PARM_CIDR )
	{
	    if ( spfic->client_ver == AF_INET )
		return data->dc.ipv4;
	    else if ( spfic->client_ver == AF_INET6 )
		return data->dc.ipv6;
	}
	break;
    }
	
    return 0;
}



int SPF_ip_match( SPF_config_t spfcid, SPF_mech_t *mech,
		  struct in_addr ipv4 )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);

    char	src_ip4_buf[ INET_ADDRSTRLEN ];
    char	dst_ip4_buf[ INET_ADDRSTRLEN ];
    char	mask_ip4_buf[ INET_ADDRSTRLEN ];

    const char	*p_err;


    struct in_addr	src_ipv4 = spfic->ipv4;
    int		cidr, mask;
	

    if ( spfic->client_ver != AF_INET )
	return FALSE;


    cidr = SPF_mech_cidr( spfcid, mech );
    if ( cidr == 0 )
	cidr = 32;
    mask = 0xffffffff << (32 - cidr);
    mask = htonl( mask );
	
    if ( spfic->debug )
    {
	p_err = inet_ntop( AF_INET, &src_ipv4.s_addr,
			   src_ip4_buf, sizeof( src_ip4_buf ) );
	if ( p_err == NULL )
	    snprintf( src_ip4_buf, sizeof( src_ip4_buf ), "ip-error" );

	p_err = inet_ntop( AF_INET, &ipv4.s_addr,
			   dst_ip4_buf, sizeof( dst_ip4_buf ) );
	if ( p_err == NULL )
	    snprintf( dst_ip4_buf, sizeof( dst_ip4_buf ), "ip-error" );

	p_err = inet_ntop( AF_INET, &mask,
			   mask_ip4_buf, sizeof( mask_ip4_buf ) );
	if ( p_err == NULL )
	    snprintf( mask_ip4_buf, sizeof( mask_ip4_buf ), "ip-error" );

	SPF_debugf( "ip_match:  %s == %s  (/%d %s):  %d",
		src_ip4_buf, dst_ip4_buf, cidr, mask_ip4_buf,
		(src_ipv4.s_addr & mask) == (ipv4.s_addr & mask));
    }

    return (src_ipv4.s_addr & mask) == (ipv4.s_addr & mask);
}


int SPF_ip_match6( SPF_config_t spfcid, SPF_mech_t *mech,
		   struct in6_addr ipv6 )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);

    char	src_ip6_buf[ INET6_ADDRSTRLEN ];
    char	dst_ip6_buf[ INET6_ADDRSTRLEN ];

    const char	*p_err;


    struct in6_addr	src_ipv6 = spfic->ipv6;
    int		cidr, mask;
    int		i;
    int		match;
    

    if ( spfic->client_ver != AF_INET6 )
	return FALSE;


    cidr = SPF_mech_cidr( spfcid, mech );
    if ( cidr == 0 )
	cidr = 128;

    match = TRUE;
    for( i = 0; i < array_elem( ipv6.s6_addr ) && match; i++ )
    {
	if ( cidr > 8 )
	    mask = 0xff;
	else if ( cidr > 0 )
	    mask = (0xff << (8 - cidr)) & 0xff;
	else
	    break;
	cidr -= 8;

	match = (src_ipv6.s6_addr[i] & mask) == (ipv6.s6_addr[i] & mask);
    }
    
	
    if ( spfic->debug )
    {
	p_err = inet_ntop( AF_INET6, &src_ipv6.s6_addr,
			   src_ip6_buf, sizeof( src_ip6_buf ) );
	if ( p_err == NULL )
	    snprintf( src_ip6_buf, sizeof( src_ip6_buf ), "ip-error" );

	p_err = inet_ntop( AF_INET6, &ipv6.s6_addr,
			   dst_ip6_buf, sizeof( dst_ip6_buf ) );
	if ( p_err == NULL )
	    snprintf( dst_ip6_buf, sizeof( dst_ip6_buf ), "ip-error" );

	SPF_debugf( "ip_match:  %s == %s  (/%d):  %d",
		src_ip6_buf, dst_ip6_buf, cidr, match );
    }

    return match;
}


#define done(result,reason,err) xdone( &output, result, reason, err, buf, &c_results )

static SPF_output_t xdone( SPF_output_t *output,
			  SPF_result_t result,
			  SPF_reason_t reason,
			  SPF_err_t err,
			  char *buf, SPF_c_results_t *c_results )
{
    output->result = result;
    output->reason = reason;
    output->err = err;
    if ( buf ) free( buf );
    SPF_free_c_results( c_results );
    return *output;
}


SPF_output_t SPF_eval_id( SPF_config_t spfcid, SPF_id_t spfid,
			    SPF_dns_config_t spfdcid,
			  int use_local_policy, int use_helo,
			  int *num_dns_mech )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_internal_t	*spfi = SPF_id2spfi(spfid);
    SPF_output_t	output;

    int		i, j;
    int		m;
    SPF_mech_t	*mech;
    SPF_mech_t	*local_policy;
    int		found_all;
    SPF_data_t	*data, *data_end;

    char	*buf = NULL;
    size_t	buf_len = 0;
    ns_type	fetch_ns_type;
    char	*lookup;

    SPF_dns_rr_t *rr_a;
    SPF_dns_rr_t *rr_aaaa;
    SPF_dns_rr_t *rr_ptr;
    SPF_dns_rr_t *rr_mx;

    SPF_err_t	err;

    char	*sender_dom, *sd, *cd;
    
    char	*pc, *ps;

    SPF_c_results_t c_results;

    SPF_output_t	inc_out;

    char	*save_cur_dom;
    int		local_num_dns_mech = 0;
    
    struct in_addr tmp_ipv4;
    struct in6_addr tmp_ipv6;
    
    int		max_ptr;
    int		max_mx;


    /*
     * make sure we were passed valid data to work with
     */
    if ( spfic == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfi == NULL )
	SPF_error( "spfid is NULL" );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );



    SPF_init_c_results( &c_results );
    SPF_init_output( &output );
    


    if ( spfic->client_ver != AF_INET && spfic->client_ver != AF_INET6 )
	return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, SPF_E_NOT_CONFIG );
    
    if ( spfic->cur_dom == NULL )
	return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, SPF_E_NOT_CONFIG );
	
    sender_dom = spfic->dp_from;
    if ( sender_dom == NULL || use_helo ) sender_dom = spfic->helo_dom;

    if ( sender_dom == NULL )
	return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, SPF_E_NOT_CONFIG );


    /*
     * localhost always gets a free ride
     */

    if ( SPF_is_loopback( spfcid ) )
	return done( SPF_RESULT_PASS, SPF_REASON_LOCALHOST, SPF_E_SUCCESS );
    

    /*
     * Do some start up stuff if we haven't recursed yet
     */

    if ( num_dns_mech == NULL )
	num_dns_mech = &local_num_dns_mech;
    if ( *num_dns_mech < 0 )
	*num_dns_mech = 0;
    
    local_policy = NULL;

    if ( use_local_policy )
    {
	/*
	 * find the location for the whitelist execution
	 *
	 * Philip Gladstone says:
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
	 */
	
	if ( spfic->local_policy.spfid )
	{
	    mech = spfi->mech_first;

	    found_all = FALSE;
	    for( m = 0; m < spfi->header.num_mech; m++ )
	    {
		if ( mech->mech_type == MECH_ALL
		     && (mech->prefix_type == PREFIX_FAIL
			 || mech->prefix_type == PREFIX_UNKNOWN
			 || mech->prefix_type == PREFIX_SOFTFAIL
			 )
		    )
		    found_all = TRUE;
	    
		if ( mech->prefix_type != PREFIX_FAIL
		     && mech->prefix_type != PREFIX_SOFTFAIL
		    )
		    local_policy = mech;

		mech = SPF_next_mech( mech );
	    }
	
	    if ( !found_all )
		local_policy = NULL;
	}
	
    }
    

    /*
     * evaluate the mechanisms
     */

    mech = spfi->mech_first;
    for( m = 0; m < spfi->header.num_mech; m++ )
    {
	if ( *num_dns_mech > spfic->max_dns_mech
	     || *num_dns_mech > SPF_MAX_DNS_MECH )
	    return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, SPF_E_BIG_DNS );
		
	switch( mech->mech_type )
	{
	case MECH_A:
	    ++*num_dns_mech;

	    data = SPF_mech_data( mech );
	    data_end = SPF_mech_end_data( mech );

	    if ( data < data_end && data->dc.parm_type == PARM_CIDR )
		data = SPF_next_data( data );
	    
	    if ( data == data_end )
		lookup = SPF_get_cur_dom( spfcid );
	    else
	    {
		err = SPF_expand( spfcid, spfdcid,
				  data, mech->parm_len,
				  &buf, &buf_len );

		if ( err == SPF_E_NO_MEMORY )
		    return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
		else if ( err )
		    return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
		lookup = buf;
	    }
	    
	    if ( spfic->client_ver == AF_INET )
		fetch_ns_type = ns_t_a;
	    else
		fetch_ns_type = ns_t_aaaa;
	    
	    rr_a = SPF_dns_lookup( spfdcid, lookup, fetch_ns_type, TRUE );
    
	    if ( spfic->debug )
		SPF_debugf( "found %d A records for %s  (herrno: %d)",
			rr_a->num_rr, lookup, rr_a->herrno );
	    
	    if( rr_a->herrno == TRY_AGAIN )
		return done( SPF_RESULT_ERROR, SPF_REASON_MECH,
			     SPF_E_DNS_ERROR );
	    
	    for( i = 0; i < rr_a->num_rr; i++ )
	    {
		if ( rr_a->rr_type != fetch_ns_type )
		    continue;

		if ( spfic->client_ver == AF_INET )
		{
		    if ( SPF_ip_match( spfcid, mech, rr_a->rr[i]->a ) )
			return done( mech->prefix_type, SPF_REASON_MECH,
				     SPF_E_SUCCESS );
		}
		else
		{
		    if ( SPF_ip_match6( spfcid, mech, rr_a->rr[i]->aaaa ) )
			return done( mech->prefix_type, SPF_REASON_MECH,
				     SPF_E_SUCCESS );
		}
	    }
	    break;
	    
	case MECH_MX:
	    ++*num_dns_mech;

	    data = SPF_mech_data( mech );
	    data_end = SPF_mech_end_data( mech );

	    if ( data < data_end && data->dc.parm_type == PARM_CIDR )
		data = SPF_next_data( data );
	    
	    if ( data == SPF_mech_end_data( mech ) )
		lookup = SPF_get_cur_dom( spfcid );
	    else
	    {
		err = SPF_expand( spfcid, spfdcid,
				  data, mech->parm_len,
				  &buf, &buf_len );

		if ( err == SPF_E_NO_MEMORY )
		    return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
		else if ( err )
		    return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
		lookup = buf;
	    }
	    
	    rr_mx = SPF_dns_dup_rr( SPF_dns_lookup( spfdcid, lookup,
						    ns_t_mx, TRUE ) );
    
	    if ( spfic->debug )
		SPF_debugf( "found %d MX records for %s  (herrno: %d)",
			rr_mx->num_rr, lookup, rr_mx->herrno );
	    
	    if( rr_mx->herrno == TRY_AGAIN )
		return done( SPF_RESULT_ERROR, SPF_REASON_MECH,
			     SPF_E_DNS_ERROR );
	    
	    max_mx = rr_mx->num_rr;
	    if ( max_mx > spfic->max_dns_mx )
		max_mx = spfic->max_dns_mx;
	    if ( max_mx > SPF_MAX_DNS_MX )
		max_mx = SPF_MAX_DNS_MX;

	    for( j = 0; j < max_mx; j++ )
	    {
		if ( rr_mx->rr_type != ns_t_mx )
		    continue;

		if ( spfic->client_ver == AF_INET )
		    fetch_ns_type = ns_t_a;
		else
		    fetch_ns_type = ns_t_aaaa;
	    
		rr_a = SPF_dns_lookup( spfdcid, rr_mx->rr[j]->mx,
				       fetch_ns_type, TRUE );
    
		if ( spfic->debug )
		    SPF_debugf( "%d: found %d A records for %s  (herrno: %d)",
			    j, rr_a->num_rr, rr_mx->rr[j]->mx, rr_a->herrno );
		if( rr_a->herrno == TRY_AGAIN )
		    return done( SPF_RESULT_ERROR, SPF_REASON_MECH,
				 SPF_E_DNS_ERROR );
	    
		for( i = 0; i < rr_a->num_rr; i++ )
		{
		    if ( rr_a->rr_type != fetch_ns_type )
			continue;

		    if ( spfic->client_ver == AF_INET )
		    {
			if ( SPF_ip_match( spfcid, mech, rr_a->rr[i]->a ) )
			{
			    SPF_dns_destroy_rr( rr_mx );

			    return done( mech->prefix_type, SPF_REASON_MECH,
					 SPF_E_SUCCESS );
			}
		    }
		    else
		    {
			if ( SPF_ip_match6( spfcid, mech, rr_a->rr[i]->aaaa ) )
			{
			    SPF_dns_destroy_rr( rr_mx );

			    return done( mech->prefix_type, SPF_REASON_MECH,
					 SPF_E_SUCCESS );
			}
		    }
		}
	    }

	    SPF_dns_destroy_rr( rr_mx );
	    break;
	    
	case MECH_PTR:
	    ++*num_dns_mech;

	    if ( mech->parm_len == 0 )
		sd = sender_dom;
	    else
	    {
		err = SPF_expand( spfcid, spfdcid,
				  SPF_mech_data( mech ), mech->parm_len,
				  &buf, &buf_len );

		if ( err == SPF_E_NO_MEMORY )
		    return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
		else if ( err )
		    return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
		sd = buf;
	    }
	    
	    
	    if ( spfic->client_ver == AF_INET )
	    {
		rr_ptr = SPF_dns_dup_rr( SPF_dns_rlookup( spfdcid, spfic->ipv4, ns_t_ptr, TRUE ) );

		if ( spfic->debug )
		{
		    char	ip4_buf[ INET_ADDRSTRLEN ];
		    
		    const char	*p_err;
		    p_err = inet_ntop( AF_INET, &spfic->ipv4.s_addr,
				       ip4_buf, sizeof( ip4_buf ) );
		    if ( p_err == NULL )
			snprintf( ip4_buf, sizeof( ip4_buf ), "ip-error" );
		    
		    SPF_debugf( "found %d PTR records for %s  (herrno: %d)",
			    rr_ptr->num_rr, ip4_buf, rr_ptr->herrno );
		}
		if( rr_ptr->herrno == TRY_AGAIN )
		    return done( SPF_RESULT_ERROR, SPF_REASON_MECH, SPF_E_DNS_ERROR );
	    

		max_ptr = rr_ptr->num_rr;
		if ( max_ptr > spfic->max_dns_ptr )
		    max_ptr = spfic->max_dns_ptr;
		if ( max_ptr > SPF_MAX_DNS_PTR )
		    max_ptr = SPF_MAX_DNS_PTR;

		for( i = 0; i < max_ptr; i++ )
		{
		    rr_a = SPF_dns_lookup( spfdcid, rr_ptr->rr[i]->ptr, ns_t_a, TRUE );

		    if ( spfic->debug )
			SPF_debugf( "%d:  found %d A records for %s  (herrno: %d)",
				i, rr_a->num_rr, rr_ptr->rr[i]->ptr, rr_a->herrno );
		    if( rr_a->herrno == TRY_AGAIN )
			return done( SPF_RESULT_ERROR, SPF_REASON_MECH, SPF_E_DNS_ERROR );
	    
		    for( j = 0; j < rr_a->num_rr; j++ )
		    {
			if ( spfic->debug )
			{
			    char	ip4_buf[ INET_ADDRSTRLEN ];
		    
			    const char	*p_err;
			    p_err = inet_ntop( AF_INET, &rr_a->rr[j]->a.s_addr,
					       ip4_buf, sizeof( ip4_buf ) );
			    if ( p_err == NULL )
				snprintf( ip4_buf, sizeof( ip4_buf ), "ip-error" );
		    
			    SPF_debugf( "%d: %d:  found %s",
				    i, j, ip4_buf );
			}

			if ( rr_a->rr[j]->a.s_addr == spfic->ipv4.s_addr )
			{

			    cd = rr_ptr->rr[i]->ptr;
			    pc = cd + strlen( cd ) - 1;
			    ps = sd + strlen( sd ) - 1;

			    if ( spfic->debug)
				SPF_debugf( "%s == %s", sd, cd );
				
			    while ( pc != cd
				    && ps != sd
				    && *pc-- == *ps-- )
				;

			    if ( spfic->debug)
				SPF_debugf( "%s == %s", ps, pc );
				
			    if ( (ps == sd && pc == cd)
				 || ( ps == sd && *(pc-1) == '.' )
				)
			    {
				SPF_dns_destroy_rr( rr_ptr );
				return done( mech->prefix_type, SPF_REASON_MECH, SPF_E_SUCCESS );
			    }
			}
		    }
		}
		SPF_dns_destroy_rr( rr_ptr );
	    }
	    
	    else if ( spfic->client_ver == AF_INET6 )
	    {
		rr_ptr = SPF_dns_dup_rr( SPF_dns_rlookup6( spfdcid, spfic->ipv6, ns_t_ptr, TRUE ) );

		if ( spfic->debug )
		{
		    char	ip6_buf[ INET6_ADDRSTRLEN ];
		    
		    const char	*p_err;
		    p_err = inet_ntop( AF_INET6, &spfic->ipv6.s6_addr,
				       ip6_buf, sizeof( ip6_buf ) );
		    if ( p_err == NULL )
			snprintf( ip6_buf, sizeof( ip6_buf ), "ip-error" );
		    
		    SPF_debugf( "found %d PTR records for %s  (herrno: %d)",
			    rr_ptr->num_rr, ip6_buf, rr_ptr->herrno );
		}
		if( rr_ptr->herrno == TRY_AGAIN )
		    return done( SPF_RESULT_ERROR, SPF_REASON_MECH, SPF_E_DNS_ERROR );
	    

		max_ptr = rr_ptr->num_rr;
		if ( max_ptr > spfic->max_dns_ptr )
		    max_ptr = spfic->max_dns_ptr;
		if ( max_ptr > SPF_MAX_DNS_PTR )
		    max_ptr = SPF_MAX_DNS_PTR;

		for( i = 0; i < max_ptr; i++ )
		{
		    rr_aaaa = SPF_dns_lookup( spfdcid, rr_ptr->rr[i]->ptr, ns_t_aaaa, TRUE );

		    if ( spfic->debug )
			SPF_debugf( "%d:  found %d AAAA records for %s  (herrno: %d)",
				i, rr_aaaa->num_rr, rr_ptr->rr[i]->ptr, rr_aaaa->herrno );
		    if( rr_aaaa->herrno == TRY_AGAIN )
			return done( SPF_RESULT_ERROR, SPF_REASON_MECH, SPF_E_DNS_ERROR );
	    
		    for( j = 0; j < rr_aaaa->num_rr; j++ )
		    {
			if ( spfic->debug )
			{
			    char	ip6_buf[ INET6_ADDRSTRLEN ];
		    
			    const char	*p_err;
			    p_err = inet_ntop( AF_INET6, &rr_aaaa->rr[j]->aaaa.s6_addr,
					       ip6_buf, sizeof( ip6_buf ) );
			    if ( p_err == NULL )
				snprintf( ip6_buf, sizeof( ip6_buf ), "ip-error" );
		    
			    SPF_debugf( "%d: %d:  found %s",
				    i, j, ip6_buf );
			}

			if ( memcmp( &rr_aaaa->rr[j]->aaaa, &spfic->ipv6,
				     sizeof( spfic->ipv6 ) ) == 0 )
			{

			    cd = rr_ptr->rr[i]->ptr;
			    pc = cd + strlen( cd ) - 1;
			    ps = sd + strlen( sd ) - 1;

			    if ( spfic->debug)
				SPF_debugf( "%s == %s", sd, cd );
				
			    while ( pc != cd
				    && ps != sd
				    && *pc-- == *ps-- )
				;

			    if ( spfic->debug)
				SPF_debugf( "%s == %s", ps, pc );
				
			    if ( (ps == sd && pc == cd)
				 || ( ps == sd && *(pc-1) == '.' )
				)
			    {
				SPF_dns_destroy_rr( rr_ptr );

				return done( mech->prefix_type, SPF_REASON_MECH, SPF_E_SUCCESS );
			    }
			}
		    }
		}
		SPF_dns_destroy_rr( rr_ptr );
	    }

	    break;
	    
	case MECH_INCLUDE:
	    ++*num_dns_mech;

	    err = SPF_expand( spfcid, spfdcid,
			      SPF_mech_data( mech ), mech->parm_len,
			      &buf, &buf_len );

	    if ( err == SPF_E_NO_MEMORY )
		return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
	    else if ( err )
		return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
	    lookup = buf;
	    
	    /*
	     * get the (compiled) SPF record
	     */
    
	    err = SPF_get_spf( spfcid, spfdcid, lookup, &c_results );

	    if ( spfic->debug > 0 )
		SPF_debugf( "include:  getting SPF record:  %s",
			SPF_strerror( err ) );
		

	    if ( err == SPF_E_SUCCESS )
	    {
		/*
		 * find out whether this configuration passes
		 */
		
		save_cur_dom = strdup( SPF_get_cur_dom( spfcid ) );
		if ( save_cur_dom == NULL )
		    return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
		SPF_set_cur_dom( spfcid, lookup );

		inc_out = SPF_eval_id( spfcid, c_results.spfid, spfdcid,
				       FALSE, FALSE, num_dns_mech );

		SPF_set_cur_dom( spfcid, save_cur_dom );
		free( save_cur_dom );
		SPF_reset_c_results( &c_results );

		if ( spfic->debug > 0 )
		    SPF_debugf( "include:  executed SPF record:  %s  result: %s  reason: %s",
			    SPF_strerror( inc_out.err ),
			    SPF_strresult( inc_out.result ),
			    SPF_strreason( inc_out.reason ) );
		
		switch ( inc_out.result )
		{
		case SPF_RESULT_PASS:
		    err = inc_out.err;
		    SPF_free_output( &inc_out );

		    return done( mech->prefix_type, SPF_REASON_MECH, err );
		    break;
		    
		case SPF_RESULT_ERROR:
		    err = inc_out.err;
		    SPF_free_output( &inc_out );

		    return done( SPF_RESULT_ERROR, SPF_REASON_MECH, err );
		    break;

		case SPF_RESULT_NEUTRAL:
		case SPF_RESULT_SOFTFAIL:
		case SPF_RESULT_FAIL:
		    SPF_free_output( &inc_out );
		    break;

		case SPF_RESULT_NONE:
		case SPF_RESULT_UNKNOWN:
		default:
		    err = inc_out.err;
		    SPF_free_output( &inc_out );

		    return done( SPF_RESULT_UNKNOWN, SPF_REASON_MECH, err );
		    break;
		}
	    }
	    else if ( err == SPF_E_DNS_ERROR )
		return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
	    else
		return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
	    

	    
	    break;
	    
	case MECH_IP4:
	    memmove( &tmp_ipv4, SPF_mech_ip4_data( mech ), sizeof( tmp_ipv4 ) );
	    if ( SPF_ip_match( spfcid, mech, tmp_ipv4 ) )
		return done( mech->prefix_type, SPF_REASON_MECH, SPF_E_SUCCESS );
	    break;
	    
	case MECH_IP6:
	    memmove( &tmp_ipv6, SPF_mech_ip6_data( mech ), sizeof( tmp_ipv6 ) );
	    if ( SPF_ip_match6( spfcid, mech, tmp_ipv6 ) )
		return done( mech->prefix_type, SPF_REASON_MECH, SPF_E_SUCCESS );
	    break;
	    
	case MECH_EXISTS:
	    ++*num_dns_mech;

	    err = SPF_expand( spfcid, spfdcid,
			      SPF_mech_data( mech ), mech->parm_len,
			      &buf, &buf_len );

	    if ( err == SPF_E_NO_MEMORY )
		return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
	    else if ( err )
		return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
	    lookup = buf;
	    
	    rr_a = SPF_dns_lookup( spfdcid, lookup, ns_t_a, FALSE );
    
	    if ( spfic->debug )
		SPF_debugf( "found %d A records for %s  (herrno: %d)",
			rr_a->num_rr, lookup, rr_a->herrno );
	    
	    if( rr_a->herrno == TRY_AGAIN )
		return done( SPF_RESULT_ERROR, SPF_REASON_MECH, SPF_E_DNS_ERROR );
	    
	    
	    if ( rr_a->num_rr > 0 )
		return done( mech->prefix_type, SPF_REASON_MECH, SPF_E_SUCCESS );
	    
	    break;
	    
	case MECH_ALL:
	    if ( mech->prefix_type == SPF_RESULT_UNKNOWN )
		err = SPF_E_UNKNOWN_MECH;
	    else
		err = SPF_E_SUCCESS;

	    return done( mech->prefix_type, SPF_REASON_MECH, err );
	    break;
	    
	case MECH_REDIRECT:
	    ++*num_dns_mech;

	    err = SPF_expand( spfcid, spfdcid,
			      SPF_mech_data( mech ), mech->parm_len,
			      &buf, &buf_len );

	    if ( err == SPF_E_NO_MEMORY )
		return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
	    else if ( err )
		return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, err );
	    lookup = buf;
	    
	    /*
	     * get the (compiled) SPF record
	     */
    
	    err = SPF_get_spf( spfcid, spfdcid, lookup, &c_results );

	    if ( spfic->debug > 0 )
		SPF_debugf( "redirect:  getting SPF record:  %s",
			SPF_strerror( err ) );
		

	    if ( err == SPF_E_SUCCESS )
	    {
		/*
		 * find out whether this configuration passes
		 */
		
		SPF_set_cur_dom( spfcid, lookup );
		inc_out = SPF_eval_id( spfcid, c_results.spfid, spfdcid,
				       TRUE, FALSE, num_dns_mech );
		SPF_reset_c_results( &c_results );

		if ( spfic->debug > 0 )
		    SPF_debugf( "redirect:  executed SPF record:  %s  result: %s  reason: %s",
			    SPF_strerror( inc_out.err ),
			    SPF_strresult( inc_out.result ),
			    SPF_strreason( inc_out.reason ) );

		output = done( inc_out.result, inc_out.reason, inc_out.err );
		SPF_free_output( &inc_out );
		
		return output;
	    }
	    else if ( err == SPF_E_DNS_ERROR )
		return done( SPF_RESULT_ERROR, SPF_REASON_NONE, err );
	    else
		return done( mech->prefix_type, SPF_REASON_MECH, err );
	    
	    break;

	default:
	    return done( SPF_RESULT_UNKNOWN, SPF_REASON_NONE, SPF_E_UNKNOWN_MECH );
	    break;
	}
	    

	/*
	 * execute the local policy
	 */

	if ( mech == local_policy )
	{
	    inc_out = SPF_eval_id( spfcid, spfic->local_policy.spfid,
				   spfdcid, FALSE, FALSE, NULL );

	    if ( spfic->debug > 0 )
		SPF_debugf( "local_policy:  executed SPF record:  %s  result: %s  reason: %s",
			    SPF_strerror( inc_out.err ),
			    SPF_strresult( inc_out.result ),
			    SPF_strreason( inc_out.reason ) );
		
	    if ( inc_out.reason != SPF_REASON_DEFAULT )
	    {
		output = done( inc_out.result, SPF_REASON_LOCAL_POLICY,
			       inc_out.err );
		SPF_free_output( &inc_out );

		return output;
	    }
	    SPF_free_output( &inc_out );

	}
	
	mech = SPF_next_mech( mech );
    }

    /* falling off the end is the same as ?all */
    return done( SPF_RESULT_NEUTRAL, SPF_REASON_DEFAULT, SPF_E_SUCCESS );
}


