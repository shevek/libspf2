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
# include <ctype.h>        /* isupper / tolower */
#endif

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
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
#ifdef HAVE_STRING_H
#include <string.h>
#endif


#include "spf.h"
#include "spf_internal.h"



SPF_err_t SPF_expand( SPF_config_t spfcid, SPF_dns_config_t spfdc,
		SPF_data_t *data, size_t data_len,
		char **buf, size_t *buf_len)
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    SPF_data_t	*d, *data_end;

    size_t	len;
    const char	*p_err;
    char	*p, *p_end;
    char	*p_back;
    char	*p_back_end;
    char	*p_forward;
    char	*p2, *p2_end;
		

    char	*var;
    char	*rev_var = NULL;
    char	*trunc_var = NULL;
    char	*url_var = NULL;
    
    char	ip4_buf[ INET_ADDRSTRLEN ];
    char	ip6_buf[ INET6_ADDRSTRLEN ];
    char	ip6_rbuf[ sizeof( struct in6_addr ) * 4 + 1 ];  /* nibbles */

    char	time_buf[ sizeof( "4294967296" ) ]; /* 2^32 seconds max	*/
    
    /* FIXME  this bogus, var should be const */
    char	client_ver_ipv4[] = "in-addr";
    char	client_ver_ipv6[] = "ip6";

    int		num_found;
    int		i;
    

    /* data_end = SPF_mech_end_data( mech ); */ /* doesn't work for mods */
    data_end = (SPF_data_t *)((char *)data + data_len);
	

    /*
     * make sure we were passed valid data to work with
     */
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );
    
    if ( spfdc == NULL )
	SPF_error( "spfdc is NULL" );
    
    if ( data == NULL )
	SPF_error( "SPF data is NULL" );
    

    /*
     * make sure the return buffer is big enough
     *
     * find max length of all variables
     */
    
    len = 0;
    for( d = data; d < data_end; d = SPF_next_data( d ) )
    {
	switch( d->ds.parm_type )
	{
	case PARM_CIDR:
	    break;

	case PARM_STRING:
	    len += d->ds.len;
	    break;

	case PARM_CLIENT_IP:
	    len += sizeof( ip6_rbuf );
	    break;

	case PARM_CLIENT_IP_P:
	    len += sizeof( ip6_buf );
	    break;

	default:
	    if ( spfic->max_var_len > 8 )
		len += spfic->max_var_len * 3; /* url encoding		*/
	    else
		len += 8 * 3;
	    break;
	}
    }
    len += sizeof( '\0' );
    

    if ( *buf_len < len )
    {
	char	*new_rec;
	size_t	new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = len + 64;

	new_rec = realloc( *buf, new_len );
	if ( new_rec == NULL )
	    return SPF_E_NO_MEMORY;

	*buf = new_rec;
	*buf_len = new_len;
    }
    memset( *buf, '\0', *buf_len );	/* cheaper than NUL at each step */
    p = *buf;
    p_end = *buf + *buf_len;



    /*
     * expand the data
     */

    for( d = data; d < data_end; d = SPF_next_data( d ) )
    {
	if ( d->dc.parm_type == PARM_CIDR )
	    continue;
	

	if ( d->ds.parm_type == PARM_STRING )
	{
	    if ( p_end - (p + d->ds.len) <= 0 ) return SPF_E_INTERNAL_ERROR;

	    memcpy( p, SPF_data_str( d ), d->ds.len );
	    p += d->ds.len;
	}
	else
	{
	    var = NULL;
	    switch( d->dv.parm_type )
	    {
	    case PARM_LP_FROM:	/* local-part of envelope-sender */
		var = spfic->lp_from;
		break;
		    
	    case PARM_ENV_FROM:	/* envelope-sender		*/
		var = spfic->env_from;
		break;
		    
	    case PARM_DP_FROM:	/* envelope-domain		*/
		var = spfic->dp_from;
		break;

	    case PARM_CUR_DOM:	/* current-domain		*/
		var = spfic->cur_dom;
		break;

	    case PARM_CLIENT_IP:	/* SMTP client IP		*/
		if ( spfic->client_ver == AF_INET )
		{
		    p_err = inet_ntop( AF_INET, &spfic->ipv4,
				       ip4_buf, sizeof( ip4_buf ) );
		    var = ip4_buf;
		}
		else if ( spfic->client_ver == AF_INET6 )
		{
		    p2 = ip6_rbuf;
		    p2_end = p2 + sizeof( ip6_rbuf );
			
		    for( i = 0; i < array_elem( spfic->ipv6.s6_addr ); i++ )
		    {
			p2 += snprintf( p2, p2_end - p2, "%.1x.%.1x.",
					spfic->ipv6.s6_addr[i] >> 4,
					spfic->ipv6.s6_addr[i] & 0xf );
		    }

		    /* squash the final '.' */
		    ip6_rbuf[ sizeof( struct in6_addr ) * 4 - 1] = '\0';

		    var = ip6_rbuf;

		}
		break;

	    case PARM_CLIENT_IP_P:	/* SMTP client IP (pretty)	*/
		if ( spfic->client_ver == AF_INET )
		{
		    p_err = inet_ntop( AF_INET, &spfic->ipv4,
				       ip4_buf, sizeof( ip4_buf ) );
		    var = ip4_buf;
		}
		else if ( spfic->client_ver == AF_INET6 )
		{
		    p_err = inet_ntop( AF_INET6, &spfic->ipv6,
				       ip6_buf, sizeof( ip6_buf ) );
		    var = ip6_buf;
		}
		break;

	    case PARM_TIME:		/* time in UTC epoch secs	*/
		snprintf( time_buf, sizeof( time_buf ), "%ld",
			  (long int) time( NULL ) );
		var = time_buf;
		break;

	    case PARM_CLIENT_DOM:	/* SMTP client domain name	*/
		var = SPF_get_client_dom( spfcid, spfdc );
		break;

	    case PARM_CLIENT_VER:	/* IP ver str - in-addr/ip6	*/
		if ( spfic->client_ver == AF_INET )
		    var = client_ver_ipv4;
		else if ( spfic->client_ver == AF_INET6 )
		    var = client_ver_ipv6;
		break;

	    case PARM_HELO_DOM:	/* HELO/EHLO domain		*/
		var = spfic->helo_dom;
		break;

	    case PARM_REC_DOM:	/* receiving domain		*/
		var = spfic->rec_dom;
		break;

	    default:
		return SPF_E_INVALID_VAR;
		break;
	    }

	    if ( var == NULL ) return SPF_E_UNINIT_VAR;
	    

	    /* reverse (and optionally truncate) */

	    if ( d->dv.rev )
	    {
		len =  strlen( var );
		rev_var = malloc( len + 1 );
		if ( rev_var == NULL )
		    return SPF_E_NO_MEMORY;

		p_back_end = p_back = var + len - 1;
		p_forward = rev_var;

		num_found = 0;
		
		while ( p_back >= var )
		{

		    if ( ( d->dv.delim_dot && *p_back == '.' )
			 || ( d->dv.delim_dash && *p_back == '-' )
			 || ( d->dv.delim_plus && *p_back == '+' )
			 || ( d->dv.delim_equal && *p_back == '=' )
			 || ( d->dv.delim_bar && *p_back == '|' )
			 || ( d->dv.delim_under && *p_back == '_' ) )
		    {
			num_found++;

			len = p_back_end - p_back;
			p_back_end = p_back - 1;
			memcpy( p_forward, p_back + 1, len );
			p_forward += len;

			if ( d->dv.num_rhs )
			    *p_forward++ = '\0';
			else
			    *p_forward++ = '.';
		    }
		    p_back--;
		}
		len = p_back_end - p_back;
		p_back_end = p_back - 1;
		memcpy( p_forward, p_back + 1, len );
		p_forward += len;
		*p_forward++ = '\0';

		if ( d->dv.num_rhs )
		{
		    p_back = rev_var;
		    while( num_found >= d->dv.num_rhs )
		    {
			p_back += strlen( p_back );
			p_back++;
			num_found--;
		    }

		    p_back_end = p_back;
		    while( num_found > 0 )
		    {
			p_back_end += strlen( p_back_end );
			*p_back_end = '.';
			num_found--;
		    }

		    memmove( rev_var, p_back, strlen( p_back ) + 1 );
		}

		var = rev_var;
	    }
	    

	    /* truncate (but no reverse)*/

	    if ( !d->dv.rev
		 &&  ( d->dv.num_rhs
		       || d->dv.delim_dash
		       || d->dv.delim_plus
		       || d->dv.delim_equal
		       || d->dv.delim_bar
		       || d->dv.delim_under
		     )
		)
	    {
		len = strlen( var );

		trunc_var = malloc( len + 1 );
		if ( trunc_var == NULL )
		    return SPF_E_NO_MEMORY;

		p_back_end = p_back = var + len - 1;
		p_forward = trunc_var;

		num_found = 0;
		
		/* do the chop */
		while ( p_back >= var )
		{
		    if ( ( d->dv.delim_dot && *p_back == '.' )
			 || ( d->dv.delim_dash && *p_back == '-' )
			 || ( d->dv.delim_plus && *p_back == '+' )
			 || ( d->dv.delim_equal && *p_back == '=' )
			 || ( d->dv.delim_bar && *p_back == '|' )
			 || ( d->dv.delim_under && *p_back == '_' ) )
		    {
			num_found++;

			if ( num_found == d->dv.num_rhs )
			    break;
		    }
		    p_back--;
		}
		len = p_back_end - p_back + 1;
		memmove( p_forward, p_back + 1, len );


		/* now we have to convert the delimeters */
		p_back = trunc_var;
		while ( *p_back != '\0' )
		{
		    if ( ( d->dv.delim_dot && *p_back == '.' )
			 || ( d->dv.delim_dash && *p_back == '-' )
			 || ( d->dv.delim_plus && *p_back == '+' )
			 || ( d->dv.delim_equal && *p_back == '=' )
			 || ( d->dv.delim_bar && *p_back == '|' )
			 || ( d->dv.delim_under && *p_back == '_' ) )
		    {
			*p_back = '.';
		    }
		    p_back++;
		}

		var = trunc_var;
	    }
	    

	    /* URL encode */

	    if ( d->dv.url_encode )
	    {
		len =  strlen( var );
		url_var = malloc( len * 3 + 1 );
		if ( url_var == NULL )
		    return SPF_E_NO_MEMORY;

		p_back = var;
		p_forward = url_var;

		/* escape non-uric characters (rfc2396) */
		while ( *p_back != '\0' )
		{
		    if ( isalnum( SPF_c2ui( *p_back  ) ) )
			*p_forward++ = *p_back++;
		    else
		    {
			switch( *p_back )
			{
			case '-':
			case '_':
			case '.':
			case '!':
			case '~':
			case '*':
			case '\'':
			case '(':
			case ')':
			    *p_forward++ = *p_back++;
			break;
			
			default:
			    snprintf( p_forward, 4, "%%%02x", *p_back );
			    p_forward += 3;
			    p_back++;
			    
			}
		    }
		}
		*p_forward = *p_back;
		
		var = url_var;
	    }
	    
		
	    /* finish up */
	    len = snprintf( p, p_end - p, "%s", var );
	    p += len;
	    if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
	    
	    if ( rev_var ) free( rev_var );
	    rev_var = NULL;

	    if ( trunc_var ) free( trunc_var );
	    trunc_var = NULL;

	    if ( url_var ) free( url_var );
	    url_var = NULL;
	}
    }


    *p++ = '\0';

    return SPF_E_SUCCESS;
}


