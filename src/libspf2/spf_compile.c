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

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif



#include "spf.h"
#include "spf_internal.h"

#define CIDR_NONE	0
#define CIDR_OPTIONAL	1
#define CIDR_ONLY	2


static SPF_err_t SPF_c_common_data_add( SPF_data_t *data, int *header_len, size_t *parm_len, size_t max_len, SPF_err_t big_err, char const **p_p, char const **p_token, int cidr_ok, int is_mod )
{
    const char	*p = *p_p;
    const char	*token = *p_token;
    const char	*real_end, *data_end;
    const char	*cur, *start;
    
    size_t	len, ds_len;

    int		str_found;
    char	*dst;
    int		c;

    SPF_err_t		comp_stat;

    len = strcspn( p, " " );
    real_end = data_end = p + len;
    start = p;
    

    /*
     * create the CIDR length info
     */
    if ( cidr_ok == CIDR_OPTIONAL  ||  cidr_ok == CIDR_ONLY ) 
    {
	start = cur = data_end - 1;

	/* find the beginning of the CIDR length notation */
	while( isdigit( SPF_c2ui( *start ) ) )
	    start--;

	if ( cur != start  &&  *start == '/' )
	{
	    /* we have at least '/nnn' */
	    data->dc.parm_type = PARM_CIDR;
	    data->dc.ipv4 = 0;
	    data->dc.ipv6 = 0;


	    /* get IPv6 CIDR length */
	    if ( start[-1] == '/' )
	    {
		data_end = start - 1;
		cur = start + 1;
		c = 0;
		while ( isdigit( SPF_c2ui( *cur ) ) )
		{
		    c *= 10;
		    c += *cur - '0';
		    cur++;
		    if ( c > 128 )
		    {
			token = start;
			p = cur;
			comp_stat = SPF_E_INVALID_CIDR;
			goto error;
		    }
		}
		if ( c == 0 ) 
		{
		    token = start;
		    p = cur;
		    comp_stat = SPF_E_INVALID_CIDR;
		    goto error;
		}
		if ( c == 128 ) c = 0;

		data->dc.ipv6 = c;

		/* now back up and see if there is a ipv4 cidr length */
		start -= 2;
		cur = start;
		while( isdigit( SPF_c2ui( *start ) ) )
		    start--;
	    }

	    /* get IPv4 CIDR length */
	    if ( cur != start  &&  *start == '/' )
	    {
		data_end = start;
		cur = start + 1;
		c = 0;
		while ( isdigit( SPF_c2ui( *cur ) ) )
		{
		    c *= 10;
		    c += *cur - '0';
		    cur++;
		    if ( c > 32 )
		    {
			token = start;
			p = cur;
			comp_stat = SPF_E_INVALID_CIDR;
			goto error;
		    }
		}
		if ( c == 0 ) 
		{
		    token = start;
		    p = cur;
		    comp_stat = SPF_E_INVALID_CIDR;
		    goto error;
		}
		if ( c == 32 ) c = 0;
		data->dc.ipv4 = c;
	    }


	    if ( data->dc.ipv4 != 0  ||  data->dc.ipv6 != 0 )
	    {
		len = sizeof( *data );
	    
		if ( *header_len + len > max_len )
		{
		    comp_stat = big_err;
		    goto error;
		}
		*header_len += len;

		if ( *parm_len + len > max_len ) /* redundant */
		{
		    comp_stat = big_err;
		    goto error;
		}
		*parm_len += len;

		data = SPF_next_data( data );
	    }
	}
    }

    if ( cidr_ok == CIDR_ONLY  &&  p != data_end )
    {
	p = start;
	comp_stat = SPF_E_INVALID_CIDR;
	goto error;
    }


    /*
     * create the data blocks
     */
    while ( p != data_end )
    {
	/* is this a string? */
	str_found = FALSE;
	dst = NULL;
	ds_len = 0;
	while ( p[0] != '%'  ||  p[1] != '{' )
	{
	    if ( !str_found )
	    {
		data->ds.parm_type = PARM_STRING;
		ds_len = data->ds.len = 0;
		ds_len = data->ds.reserved = 0;
		dst = SPF_data_str( data );
		str_found = TRUE;
	    }
	    
	    token = p;
	    len = strcspn( p, " %" );
	    if ( p + len > data_end )
		len = data_end - p;
	    p += len;

	    memcpy( dst, token, len );
	    ds_len += len;
	    dst += len;

	    if ( p == data_end  ||  p[1] == '{' )
	    {
		
#if 0
		/* align to an even length */
		if ( (ds_len & 1) == 1 )
		{
		    *dst++ = '\0';
		    ds_len++;
		}
#endif

		break;
	    }
	    

	    /* must be % escape code */
	    p++;
	    switch ( *p )
	    {
	    case '%':
		*dst++ = '%';
		ds_len++;
		break;
		
	    case '_':
		*dst++ = ' ';
		ds_len++;
		break;

	    case '-':
		*dst++ = '%';
		*dst++ = '2';
		*dst++ = '0';
		ds_len += 3;
		break;

	    default:
		*dst++ = *p;
		ds_len++;
		/* FIXME   issue a warning? */
#if 0
		/* SPF spec says to treat it as a literal */
		comp_stat = SPF_E_INVALID_ESC;
		goto error;
#endif
		break;
	    }
	    p++;
	}
    
	    
	if ( str_found )
	{
	    if ( ds_len > SPF_MAX_STR_LEN )
	    {
		comp_stat = SPF_E_BIG_STRING;
		goto error;
	    }
	    data->ds.len = ds_len;

	    len = sizeof( *data ) + ds_len;
	    
	    if ( *header_len + len > max_len )
	    {
		comp_stat = big_err;
		goto error;
	    }
	    *header_len += len;

	    if ( *parm_len + len > max_len ) /* redundant */
	    {
		comp_stat = big_err;
		goto error;
	    }
	    *parm_len += len;

	    data = SPF_next_data( data );
	}
	
	/* end of string? */
	if ( *p != '%' )
	    break;
	

	/* this must be a variable */
	p += 2;
	token = p;

	/* URL encoding */
	c = *p;
	if ( isupper( SPF_c2ui( c ) ) )
	{
	    data->dv.url_encode = TRUE;
	    c = tolower(c);
	}
	else
	    data->dv.url_encode = FALSE;

	switch ( c )
	{
	case 'l':		/* local-part of envelope-sender */
	    data->dv.parm_type = PARM_LP_FROM;
	    break;

	case 's':		/* envelope-sender		*/
	    data->dv.parm_type = PARM_ENV_FROM;
	    break;

	case 'o':		/* envelope-domain		*/
	    data->dv.parm_type = PARM_DP_FROM;
	    break;

	case 'd':		/* current-domain		*/
	    data->dv.parm_type = PARM_CUR_DOM;
	    break;

	case 'i':		/* SMTP client IP		*/
	    data->dv.parm_type = PARM_CLIENT_IP;
	    break;

	case 'c':		/* SMTP client IP (pretty)	*/
	    data->dv.parm_type = PARM_CLIENT_IP_P;
	    break;

	case 't':		/* time in UTC epoch secs	*/
	    if ( !is_mod )
	    {
		comp_stat = SPF_E_INVALID_VAR;
		goto error;
	    }
	    data->dv.parm_type = PARM_TIME;
	    break;

	case 'p':		/* SMTP client domain name	*/
	    data->dv.parm_type = PARM_CLIENT_DOM;
	    break;

	case 'v':		/* IP ver str - in-addr/ip6	*/
	    data->dv.parm_type = PARM_CLIENT_VER;
	    break;

	case 'h':		/* HELO/EHLO domain		*/
	    data->dv.parm_type = PARM_HELO_DOM;
	    break;

	case 'r':		/* receiving domain		*/
	    data->dv.parm_type = PARM_REC_DOM;
	    break;

	default:
	    comp_stat = SPF_E_INVALID_VAR;
	    goto error;
	    break;
	}
	p++;
	token = p;
	    
	/* get the number of subdomains to truncate to */
	c = 0;
	while ( isdigit( SPF_c2ui( *p ) ) )
	{
	    c *= 10;
	    c += *p - '0';
	    p++;
	}
	if ( c > 15  ||  (c == 0 && p != token) )
	{
	    comp_stat = SPF_E_BIG_SUBDOM;
	    goto error;
	}
	data->dv.num_rhs = c;
	token = p;
	    
	/* should the string be reversed? */
	if ( *p == 'r' )
	{
	    data->dv.rev = 1;
	    p++;
	}
	else
	    data->dv.rev = FALSE;
	token = p;


	/* check for delimiters */
	data->dv.delim_dot = FALSE;
	data->dv.delim_dash = FALSE;
	data->dv.delim_plus = FALSE;
	data->dv.delim_equal = FALSE;
	data->dv.delim_bar = FALSE;
	data->dv.delim_under = FALSE;

	if ( *p == '}' )
	    data->dv.delim_dot = TRUE;

	while( *p != '}' )
	{
	    token = p;
	    switch( *p )
	    {
	    case '.':
		data->dv.delim_dot = TRUE;
		break;
		    
	    case '-':
		data->dv.delim_dash = TRUE;
		break;
		    
	    case '+':
		data->dv.delim_plus = TRUE;
		break;
		    
	    case '=':
		data->dv.delim_equal = TRUE;
		break;
		    
	    case '|':
		data->dv.delim_bar = TRUE;
		break;
		    
	    case '_':
		data->dv.delim_under = TRUE;
		break;

	    default:
		comp_stat = SPF_E_INVALID_DELIM;
		goto error;
		break;
	    }
	    p++;
	}
	p++;
	token = p;

	len = sizeof( *data );
	if ( *header_len + len > max_len )
	{
	    comp_stat = big_err;
	    goto error;
	}
	*header_len += len;

	if ( *parm_len + len > max_len ) /* redundant */
	{
	    comp_stat = big_err;
	    goto error;
	}
	*parm_len += len;

	data = SPF_next_data( data );
    }
    
    comp_stat = SPF_E_SUCCESS;

  error:
    *p_p = real_end;
    *p_token = token;
    
    return comp_stat;
}


SPF_err_t SPF_c_mech_add( SPF_id_t spfid, int mech_type, int prefix )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    if ( spfi->mech_buf_len - spfi->header.mech_len < sizeof( SPF_mech_t ) )
    {
	SPF_mech_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mech_buf_len + 8 * sizeof( SPF_mech_t ) + 64;

	new_first = realloc( spfi->mech_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mech_last = (SPF_mech_t *)((char *)new_first + ((char *)spfi->mech_last - (char *)spfi->mech_first));
	spfi->mech_first = new_first;
	spfi->mech_buf_len = new_len;
    }
    
    if ( spfi->header.num_mech > 0 )
	spfi->mech_last = SPF_next_mech( spfi->mech_last );
    spfi->mech_last->mech_type = mech_type;
    spfi->mech_last->prefix_type = prefix;
    spfi->mech_last->parm_len = 0;

    if ( spfi->header.mech_len + sizeof( SPF_mech_t ) > SPF_MAX_MECH_LEN )
	return SPF_E_BIG_MECH;

    spfi->header.mech_len += sizeof( SPF_mech_t );
    spfi->header.num_mech++;

    return SPF_E_SUCCESS;
}


SPF_err_t SPF_c_mech_data_add( SPF_id_t spfid, char const **p_p, char const **p_token, int cidr_ok )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    const char	*p = *p_p;
    
    size_t	len;

    SPF_mech_t  *mech;
    SPF_data_t  *data;
    
    SPF_err_t	comp_stat;

    size_t	header_len;
    size_t	parm_len;


    /*
     * expand the buffer
     *
     * in the worse case, data can be "%-%-%-%-..." which will be
     * converted into "%20%20%20%20....", a 3/2 increase, plus you have to
     * add in the overhead of the data struct and a possible rounding to
     * an even number of bytes.
     */

    len = strcspn( p, " " );
    if ( spfi->mech_buf_len - spfi->header.mech_len < (3 * len) / 2 + 8 )
    {
	SPF_mech_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mech_buf_len + 8 * len + 64;

	new_first = realloc( spfi->mech_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mech_last = (SPF_mech_t *)((char *)new_first + ((char *)spfi->mech_last - (char *)spfi->mech_first));
	spfi->mech_first = new_first;
	spfi->mech_buf_len = new_len;
    }
    
    mech = spfi->mech_last;
    data = SPF_mech_data( mech );


    header_len = spfi->header.mech_len;
    parm_len = mech->parm_len;
    
    comp_stat = SPF_c_common_data_add( data, &header_len, &parm_len, SPF_MAX_MECH_LEN, SPF_E_BIG_MECH, p_p, p_token, cidr_ok, FALSE );
    
    spfi->header.mech_len = header_len;
    mech->parm_len = parm_len;
    
    return comp_stat;
}


SPF_err_t SPF_c_mech_ip4_add( SPF_id_t spfid, char const **p_p, char const **p_token )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    const char	*p = *p_p;
    const char	*token = *p_token;
    const char	*real_end, *data_end;
    const char	*cur, *start;
    
    SPF_err_t	err;
    int		c;
    size_t	len;

    SPF_mech_t  *mech;
    struct in_addr  *data;
    
    SPF_err_t	comp_stat;

    char	ip4_buf[ INET_ADDRSTRLEN ];

    len = strcspn( p, " " );
    real_end = data_end = p + len;
    start = p;

    /*
     * expand the buffer
     */

    len = sizeof( struct in_addr );
    if ( spfi->mech_buf_len - spfi->header.mech_len < len )
    {
	SPF_mech_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mech_buf_len + 8 * len + 64;

	new_first = realloc( spfi->mech_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mech_last = (SPF_mech_t *)((char *)new_first + ((char *)spfi->mech_last - (char *)spfi->mech_first));
	spfi->mech_first = new_first;
	spfi->mech_buf_len = new_len;
    }
    
    mech = spfi->mech_last;
    data = SPF_mech_ip4_data( mech );


    /*
     * create the CIDR length info
     */
    start = cur = data_end - 1;

    /* find the beginning of the CIDR length notation */
    while( isdigit( SPF_c2ui( *start ) ) )
	start--;

    if ( cur != start  &&  *start == '/' )
    {
	/* get IPv4 CIDR length */
	cur = start + 1;
	c = 0;
	while ( isdigit( SPF_c2ui( *cur ) ) )
	{
	    c *= 10;
	    c += *cur - '0';
	    cur++;
	    if ( c > 32 )
	    {
		token = start;
		p = cur;
		comp_stat = SPF_E_INVALID_CIDR;
		goto error;
	    }
	}
	if ( c == 0 ) 
	{
	    token = start;
	    p = cur;
	    comp_stat = SPF_E_INVALID_CIDR;
	    goto error;
	}
	if ( c == 32 ) c = 0;

	mech->parm_len = c;
	data_end = start;
    }


    /*
     * create the data block
     */

    len =  data_end - p;
    if ( len > sizeof( ip4_buf ) - 1 )
    {
	comp_stat = SPF_E_INVALID_IP4;
	goto error;
    }
		    
    memcpy( ip4_buf, p, len );
    ip4_buf[ len ] = '\0';
    err = inet_pton( AF_INET, ip4_buf,
		     data );
    if ( err <= 0 )
    {
	comp_stat = SPF_E_INVALID_IP4;
	goto error;
    }
		    

    len = sizeof( *data );
	    
    if ( spfi->header.mech_len + len > SPF_MAX_MECH_LEN )
    {
	comp_stat = SPF_E_BIG_MECH;
	goto error;
    }

    spfi->header.mech_len += len;

    comp_stat = SPF_E_SUCCESS;

  error:
    *p_p = real_end;
    *p_token = token;
    
    return comp_stat;
}


SPF_err_t SPF_c_mech_ip6_add( SPF_id_t spfid, char const **p_p, char const **p_token )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    const char	*p = *p_p;
    const char	*token = *p_token;
    const char	*real_end, *data_end;
    const char	*cur, *start;
    
    SPF_err_t	err;
    int		c;
    size_t	len;

    SPF_mech_t  *mech;
    struct in6_addr  *data;
    
    SPF_err_t	comp_stat;

    char	ip6_buf[ INET6_ADDRSTRLEN ];

    len = strcspn( p, " " );
    real_end = data_end = p + len;
    start = p;

    /*
     * expand the buffer
     */

    len = sizeof( struct in_addr );
    if ( spfi->mech_buf_len - spfi->header.mech_len < len )
    {
	SPF_mech_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mech_buf_len + 8 * len + 64;

	new_first = realloc( spfi->mech_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mech_last = (SPF_mech_t *)((char *)new_first + ((char *)spfi->mech_last - (char *)spfi->mech_first));
	spfi->mech_first = new_first;
	spfi->mech_buf_len = new_len;
    }
    
    mech = spfi->mech_last;
    data = SPF_mech_ip6_data( mech );


    /*
     * create the CIDR length info
     */
    start = cur = data_end - 1;

    /* find the beginning of the CIDR length notation */
    while( isdigit( SPF_c2ui( *start ) ) )
	start--;

    if ( cur != start  &&  *start == '/' )
    {
	/* get IPv6 CIDR length */
	cur = start + 1;
	c = 0;
	while ( isdigit( SPF_c2ui( *cur ) ) )
	{
	    c *= 10;
	    c += *cur - '0';
	    cur++;
	    if ( c > 128 )
	    {
		token = start;
		p = cur;
		comp_stat = SPF_E_INVALID_CIDR;
		goto error;
	    }
	}
	if ( c == 0 ) 
	{
	    token = start;
	    p = cur;
	    comp_stat = SPF_E_INVALID_CIDR;
	    goto error;
	}
	if ( c == 128 ) c = 0;

	mech->parm_len = c;
	data_end = start;
    }


    /*
     * create the data block
     */

    len =  data_end - p;
    if ( len > sizeof( ip6_buf ) - 1 )
    {
	comp_stat = SPF_E_INVALID_IP6;
	goto error;
    }
		    
    memcpy( ip6_buf, p, len );
    ip6_buf[ len ] = '\0';
    err = inet_pton( AF_INET6, ip6_buf,
		     data );
    if ( err <= 0 )
    {
	comp_stat = SPF_E_INVALID_IP6;
	goto error;
    }
		    

    len = sizeof( *data );
	    
    if ( spfi->header.mech_len + len > SPF_MAX_MECH_LEN )
    {
	comp_stat = SPF_E_BIG_MECH;
	goto error;
    }

    spfi->header.mech_len += len;

    comp_stat = SPF_E_SUCCESS;

  error:
    *p_p = real_end;
    *p_token = token;
    
    return comp_stat;
}


SPF_err_t SPF_c_mod_add( SPF_id_t spfid, const char *mod_name, size_t name_len )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);
    size_t	len;

    if ( spfi->mod_buf_len - spfi->header.mod_len
	< sizeof( SPF_mod_t ) + name_len )
    {
	SPF_mod_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mod_buf_len + 8 * (sizeof( SPF_mod_t ) + name_len) + 64;

	new_first = realloc( spfi->mod_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mod_last = (SPF_mod_t *)((char *)new_first + ((char *)spfi->mod_last - (char *)spfi->mod_first));
	spfi->mod_first = new_first;
	spfi->mod_buf_len = new_len;
    }
    
    if ( spfi->header.num_mod > 0 )
	spfi->mod_last = SPF_next_mod( spfi->mod_last );

    if ( name_len > SPF_MAX_MOD_LEN )
	return SPF_E_BIG_MOD;

    spfi->mod_last->name_len = name_len;
    spfi->mod_last->data_len = 0;
    len = sizeof( SPF_mod_t ) + name_len;

    if ( spfi->header.mod_len + len > SPF_MAX_MOD_LEN )
	return SPF_E_BIG_MOD;

    memcpy( SPF_mod_name( spfi->mod_last ), mod_name, name_len );

    spfi->header.mod_len += len;
    spfi->header.num_mod++;

    return SPF_E_SUCCESS;
}


SPF_err_t SPF_c_mod_data_add( SPF_id_t spfid, char const **p_p, char const **p_token, int cidr_ok )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    const char	*p = *p_p;
    
    size_t	len;

    SPF_mod_t	*mod;
    SPF_data_t  *data;
    
    SPF_err_t	comp_stat;

    size_t	header_len;
    size_t	parm_len;


    /*
     * expand the buffer
     *
     * in the worse case, data can be "%-%-%-%-..." which will be
     * converted into "%20%20%20%20....", a 3/2 increase, plus you have to
     * add in the overhead of the data struct and a possible rounding to
     * an even number of bytes.
     */

    len = strcspn( p, " " );
    if ( spfi->mod_buf_len - spfi->header.mod_len < (3 * len) / 2 + 8 )
    {
	SPF_mod_t *new_first;
	size_t	   new_len;
	
	/* FIXME  dup code */
	/* allocate lots so we don't have to remalloc often */
	new_len = spfi->mod_buf_len + 8 * len + 64;

	new_first = realloc( spfi->mod_first, new_len );
	if ( new_first == NULL )
	    return SPF_E_NO_MEMORY;

	spfi->mod_last = (SPF_mod_t *)((char *)new_first + ((char *)spfi->mod_last - (char *)spfi->mod_first));
	spfi->mod_first = new_first;
	spfi->mod_buf_len = new_len;
    }
    
    mod = spfi->mod_last;
    data = SPF_mod_data( mod );


    header_len = spfi->header.mod_len;
    parm_len = mod->data_len;
    
    comp_stat = SPF_c_common_data_add( data, &header_len, &parm_len, SPF_MAX_MOD_LEN, SPF_E_BIG_MOD, p_p, p_token, cidr_ok, TRUE );
    
    spfi->header.mod_len = header_len;
    mod->data_len = parm_len;
    
    return comp_stat;
}


void SPF_lint( SPF_id_t spfid, SPF_c_results_t *c_results )
{
    SPF_data_t	*d, *data_end;

    char	*s;
    char	*s_end;

    int		found_non_ip;
    int		found_valid_tld;
    

    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    SPF_mech_t  *mech;
    SPF_data_t  *data;
    

    size_t	header_len;

    int		i;


    header_len = spfi->header.mech_len;
    

    /* FIXME  these warnings suck.  Should call SPF_id2str to give more
     * context. */

    /* FIXME  there shouldn't be a limit of just one warning */

    mech = spfi->mech_first;
    for( i = 0; i < spfi->header.num_mech; i++, mech = SPF_next_mech( mech ) )
    {
	if ( ( mech->mech_type == MECH_ALL
	       || mech->mech_type == MECH_REDIRECT )
	     && i != spfi->header.num_mech - 1 )
	{
	    if ( c_results->err_msg == NULL
		 || c_results->err_msg_len < SPF_C_ERR_MSG_SIZE )
	    {
		char *new_err_msg;
		
		new_err_msg = realloc( c_results->err_msg, SPF_C_ERR_MSG_SIZE );
		if ( new_err_msg == NULL )
		    return;
		c_results->err_msg = new_err_msg;
		c_results->err_msg_len = SPF_C_ERR_MSG_SIZE;
	    }


	    snprintf( c_results->err_msg, c_results->err_msg_len,
		      "Warning: %s",
		      SPF_strerror( SPF_E_MECH_AFTER_ALL ) );
	}

	/*
	 * if we are dealing with a mechanism, make sure that the data
	 * at least looks like a valid host name.
	 *
	 * note: this routine isn't called to handle ip4: and ip6: and all
	 * the other mechanisms require a host name.
	 */

	if ( mech->mech_type == MECH_IP4
	     || mech->mech_type == MECH_IP6 )
	    continue;

	data = SPF_mech_data( mech );
	data_end = SPF_mech_end_data( mech );
	if ( data == data_end )
	    continue;

	if ( data->dc.parm_type == PARM_CIDR )
	{
	    data = SPF_next_data( data );
	    if ( data == data_end )
		continue;
	}
	

	found_valid_tld = FALSE;
	found_non_ip = FALSE;

	for( d = data; d < data_end; d = SPF_next_data( d ) )
	{
	    switch( d->dv.parm_type )
	    {
	    case PARM_CIDR:
		SPF_error( "Multiple CIDR parameters found" );
		break;
		
	    case PARM_CLIENT_IP:
	    case PARM_CLIENT_IP_P:
	    case PARM_LP_FROM:
		found_valid_tld = FALSE;
		break;

	    case PARM_STRING:
		found_valid_tld = FALSE;

		s = SPF_data_str( d );
		s_end = s + d->ds.len;
		for( ; s < s_end; s++ )
		{
		    if ( !isdigit( SPF_c2ui( *s ) ) && *s != '.' && *s != ':' )
			found_non_ip = TRUE;

		    if ( *s == '.' ) 
			found_valid_tld = TRUE;
		    else if ( !isalpha( SPF_c2ui( *s ) ) )
			found_valid_tld = FALSE;
		}
		break;

	    default:
		found_non_ip = TRUE;
		found_valid_tld = TRUE;
	    
		break;
	    }
	}

	if ( !found_valid_tld || !found_non_ip )
	{
	    if ( c_results->err_msg == NULL
		 || c_results->err_msg_len < SPF_C_ERR_MSG_SIZE )
	    {
		char *new_err_msg;
		
		new_err_msg = realloc( c_results->err_msg, SPF_C_ERR_MSG_SIZE );
		if ( new_err_msg == NULL )
		    return;
		c_results->err_msg = new_err_msg;
		c_results->err_msg_len = SPF_C_ERR_MSG_SIZE;
	    }

	    if ( !found_non_ip )
	    {
		snprintf( c_results->err_msg, c_results->err_msg_len,
			  "Warning: %s",
			  SPF_strerror( SPF_E_BAD_HOST_IP ) );
	    }
	    else if ( !found_valid_tld )
	    {
		snprintf( c_results->err_msg, c_results->err_msg_len,
			  "Warning: %s",
			  SPF_strerror( SPF_E_BAD_HOST_TLD ) );
	    }
	}

    }

    /* FIXME check for modifiers that should probably be mechanisms */
}



/*
 * The SPF compiler.
 *
 * It converts the SPF record in string format that is easy for people
 * to deal with into a compact binary format that is easy for
 * computers to deal with.
 */

SPF_err_t SPF_compile( SPF_config_t spfcid, const char *record, SPF_c_results_t *c_results )
{
    SPF_id_t		spfid;
    SPF_iconfig_t	*spfic = SPF_cid2spfic( spfcid );
    
    SPF_err_t	comp_stat;
    
    const char	*p, *token;
    char	*p2, *p2_end;
    
    int		prefix, mech;
    int		mech_len;

    SPF_err_t	err;
    int		c;
    
    int		num_dns_mech = 0;
    

    /* FIXME  there shouldn't be a limit of just one error message,
     * we should continue parsing the rest of the record. */


    /*
     * make sure we were passed valid data to work with
     */
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( record == NULL )
	SPF_error( "SPF record is NULL" );

    if ( c_results == NULL )
	SPF_error( "c_results is NULL" );


    /*
     * initialize the SPF data
     */
    SPF_reset_c_results( c_results );

    if ( c_results->spfid == NULL ) c_results->spfid = SPF_create_id();
    spfid = c_results->spfid;
    
    if ( spfid == NULL )
    {
	comp_stat = SPF_E_NO_MEMORY;
	goto error;
    }
    
    SPF_reset_id( spfid );



    
    /*
     * See if this is record is even an SPF record
     */
    p = record;
    token = p;

    if ( strncmp( p, SPF_VER_STR, sizeof( SPF_VER_STR )-1 ) != 0 )
    {
	comp_stat = SPF_E_NOT_SPF;
	goto error;
    }
    p += sizeof( SPF_VER_STR ) - 1;

    if ( *p != '\0' && *p != ' ' )
    {
	comp_stat = SPF_E_NOT_SPF;
	goto error;
    }
    token = p;
    
    
    /*
     * parse the SPF record
     */
    while( *p != '\0' )
    {
	/* skip to the next token */
	while( *p == ' ' )
	    p++;
	token = p;

	if (*p == '\0' )
	    break;

	/* see if we have a valid prefix */
	prefix = PREFIX_UNKNOWN;
	switch( *p )
	{
	case '+':
	    prefix = PREFIX_PASS;
	    p++;
	    break;
	    
	case '-':
	    prefix = PREFIX_FAIL;
	    p++;
	    break;
	    
	case '~':
	    prefix = PREFIX_SOFTFAIL;
	    p++;
	    break;
	    
	case '?':
	    prefix = PREFIX_NEUTRAL;
	    p++;
	    break;
	}
	if ( ispunct( SPF_c2ui( *p ) ) )
	{
	    comp_stat = SPF_E_INVALID_PREFIX;
	    goto error;
	}
	token = p;
	    
	/* get the mechanism/modifier */
	if ( isalpha( SPF_c2ui( *p  ) ) )
	    while ( isalnum( SPF_c2ui( *p  ) ) || *p == '_' || *p == '-' )
		p++;


	/* See if we have a modifier or a prefix */
	mech_len = p - token;
	c = *p;
	if ( strncmp( token, "default=", sizeof( "default=" )-1 ) == 0 )
	{
	    c = ':';
	    p += strcspn( p, " " );
	    mech_len = p - token;
	}
	else if ( strncmp( token, "redirect=", sizeof( "redirect=" )-1 ) == 0 )
	    c = ':';
	else if ( strncmp( token, "ip4:", sizeof( "ip4:" )-1 ) != 0
		  && strncmp( token, "ip6:", sizeof( "ip6:" )-1 ) != 0 
		  && strncmp( token, "exp-text=", sizeof( "exp-text=" )-1 ) != 0 )
	{
	    for( p = token; p < token + mech_len; p++ )
	    {
		if ( !isalpha( SPF_c2ui( *p  ) ) )
		{
		    comp_stat = SPF_E_INVALID_CHAR;
		    goto error;
		}
	    }
	}
	
	switch ( c ) 
	{
	case ':':
	case '/':
	case ' ':
	case '\0':
	    
	    /*
	     * parse the mechanism
	     */

	    /* mechanisms default to PREFIX_PASS */
	    if ( prefix == PREFIX_UNKNOWN )
		prefix = PREFIX_PASS;
	    
	    
	    if ( mech_len == sizeof( "a" )-1 
		 && strncmp( token, "a", mech_len ) == 0 )
		mech = MECH_A;
	    else if ( mech_len == sizeof( "mx" )-1 
		      && strncmp( token, "mx", mech_len ) == 0 )
		mech = MECH_MX;
	    else if ( mech_len == sizeof( "ptr" )-1 
		      && strncmp( token, "ptr", mech_len ) == 0 )
		mech = MECH_PTR;
	    else if ( mech_len == sizeof( "include" )-1 
		      && strncmp( token, "include", mech_len ) == 0 )
		mech = MECH_INCLUDE;
	    else if ( mech_len == sizeof( "ip4" )-1 
		      && strncmp( token, "ip4", mech_len ) == 0 )
		mech = MECH_IP4;
	    else if ( mech_len == sizeof( "ip6" )-1 
		      && strncmp( token, "ip6", mech_len ) == 0 )
		mech = MECH_IP6;
	    else if ( mech_len == sizeof( "exists" )-1 
		      && strncmp( token, "exists", mech_len ) == 0 )
		mech = MECH_EXISTS;
	    else if ( mech_len == sizeof( "all" )-1 
		      && strncmp( token, "all", mech_len ) == 0 )
		mech = MECH_ALL;
	    else if ( mech_len == sizeof( "default=allow" )-1 
		      && strncmp( token, "default=allow", mech_len ) == 0 )
	    {
		mech = MECH_ALL;
		prefix = PREFIX_PASS;
		c = *p;
	    }
	    else if ( mech_len == sizeof( "default=softfail" )-1 
		      && strncmp( token, "default=softfail", mech_len ) == 0 )
	    {
		mech = MECH_ALL;
		prefix = PREFIX_SOFTFAIL;
		c = *p;
	    }
	    else if ( mech_len == sizeof( "default=deny" )-1 
		      && strncmp( token, "default=deny", mech_len ) == 0 )
	    {
		mech = MECH_ALL;
		prefix = PREFIX_FAIL;
		c = *p;
	    }
	    else if ( strncmp( token, "default=", sizeof( "default=" )-1 ) == 0 )
	    {
		comp_stat = SPF_E_INVALID_OPT;
		goto error;
	    }
	    else if ( mech_len == sizeof( "redirect" )-1 
		      && strncmp( token, "redirect", mech_len ) == 0 )
		/* FIXME  the redirect mechanism needs to be moved to the very end */
		mech = MECH_REDIRECT;
	    else
	    {
		comp_stat = SPF_E_UNKNOWN_MECH;
		goto error;
	    }
	    token = p;
	    
	    err = SPF_c_mech_add( spfid, mech, prefix );
	    if ( err )
	    {
		comp_stat = err;
		goto error;
	    }

	    if ( c == ':' )
	    {
		switch( mech )
		{
		case MECH_A:
		case MECH_MX:
		    num_dns_mech++;

		    p++;
		    err = SPF_c_mech_data_add( spfid, &p, &token, CIDR_OPTIONAL );
		    if ( err )
		    {
			comp_stat = err;
			goto error;
		    }
		    break;

		case MECH_PTR:
		case MECH_INCLUDE:
		case MECH_EXISTS:
		case MECH_REDIRECT:
		    num_dns_mech++;
		    
		    p++;
		    err = SPF_c_mech_data_add( spfid, &p, &token, CIDR_NONE );
		    if ( err )
		    {
			comp_stat = err;
			goto error;
		    }
		    break;

		case MECH_ALL:
		    comp_stat = SPF_E_INVALID_OPT;
		    goto error;
		    break;
		    
		case MECH_IP4:
		    p++;
		    err = SPF_c_mech_ip4_add( spfid, &p, &token );
		    if ( err )
		    {
			comp_stat = err;
			goto error;
		    }
		    break;

		case MECH_IP6:
		    p++;
		    err = SPF_c_mech_ip6_add( spfid, &p, &token );
		    if ( err )
		    {
			comp_stat = err;
			goto error;
		    }
		    break;

		default:
		    comp_stat = SPF_E_INTERNAL_ERROR;
		    goto error;
		    break;
		}

	    
	    }
	    else if ( *p == '/' )
	    {
		switch( mech )
		{
		case MECH_A:
		case MECH_MX:
		    num_dns_mech++;

		    err = SPF_c_mech_data_add( spfid, &p, &token, CIDR_ONLY );
		    if ( err )
		    {
			comp_stat = err;
			goto error;
		    }
		    break;

		case MECH_PTR:
		case MECH_INCLUDE:
		case MECH_EXISTS:
		case MECH_REDIRECT:
		case MECH_ALL:
		case MECH_IP4:
		case MECH_IP6:
		    comp_stat = SPF_E_INVALID_CIDR;
		    goto error;
		    break;
		    
		default:
		    comp_stat = SPF_E_INTERNAL_ERROR;
		    goto error;
		    break;
		}
	    }
	    else if ( *p == ' ' || *p == '\0' )
	    {
		switch( mech )
		{
		case MECH_A:
		case MECH_MX:
		case MECH_PTR:
		    num_dns_mech++;
		    break;

		case MECH_ALL:
		    break;

		case MECH_INCLUDE:
		case MECH_IP4:
		case MECH_IP6:
		case MECH_EXISTS:
		case MECH_REDIRECT:
		    comp_stat = SPF_E_MISSING_OPT;
		    goto error;
		    break;
		    
		default:
		    comp_stat = SPF_E_INTERNAL_ERROR;
		    goto error;
		    break;
		}
	    } else {
		comp_stat = SPF_E_SYNTAX;
		goto error;
	    }

	    if ( num_dns_mech > spfic->max_dns_mech
		 || num_dns_mech > SPF_MAX_DNS_MECH )
	    {
		comp_stat = SPF_E_BIG_DNS;
		goto error;
	    }
		
	    break;

	case '=':
	    
	    /*
	     * parse the modifier
	     */

	    /* modifiers can't have prefixes */
	    if ( prefix != PREFIX_UNKNOWN )
	    {
		comp_stat = SPF_E_MOD_W_PREF;
		goto error;
	    }

	    /* FIXME  reject duplicate mods?  Or are dup mods a feature? */

	    err = SPF_c_mod_add( spfid, token, p - token );
	    if ( err )
	    {
		comp_stat = err;
		goto error;
	    }
	    p++;
	    token = p;
	    
	    err = SPF_c_mod_data_add( spfid, &p, &token, CIDR_OPTIONAL );
	    if ( err )
	    {
		comp_stat = err;
		goto error;
	    }

	    break;
	    
	    
	default:
	    comp_stat = SPF_E_INVALID_CHAR;
	    goto error;
	    break;
	}
    }
    

    /*
     * check for common mistakes
     */
    SPF_lint( spfid, c_results );


    /*
     * do final cleanup on the record
     */

    /* FIXME realloc (shrink) spfi buffers? */

    return SPF_E_SUCCESS;



    /*
     * common error handling
     */
  error:
    c_results->token = token;
    c_results->token_len = p - token;
    c_results->error_loc = p;

    p += strcspn( p, " " );
    while( token >= record && *token != ' ' )
	token--;
    token++;

    c_results->expression = token;
    c_results->expression_len = p - token;

    /* reset everthing to scratch */
    SPF_reset_id( spfid );

    /* add in the "unknown" mechanism here */
    err = SPF_c_mech_add( spfid, MECH_ALL, PREFIX_UNKNOWN );
    if ( err )			/* this can't(?) happen		*/
	comp_stat = err;

    c_results->err = comp_stat;

    /*
     * format a nice error message
     */
    if ( c_results->err_msg == NULL
	 || c_results->err_msg_len < SPF_C_ERR_MSG_SIZE )
    {
	char *new_err_msg;
		
	new_err_msg = realloc( c_results->err_msg, SPF_C_ERR_MSG_SIZE );
	if ( new_err_msg != NULL )
	{
	    c_results->err_msg = new_err_msg;
	    c_results->err_msg_len = SPF_C_ERR_MSG_SIZE;
	}
    }
    
    p2 = c_results->err_msg;
    if ( p2 != NULL )
    {
	p2_end = p2 + c_results->err_msg_len - 1;
	p2 += snprintf( p2, p2_end - p2, "%s",
			   SPF_strerror( comp_stat ) );
	if ( p2 > p2_end ) p2 = p2_end;
    
	if ( c_results->token == c_results->expression
	     && c_results->token_len == c_results->expression_len )
	    p2 += snprintf( p2, p2_end - p2,
			       " in \"%.*s\".",
			       c_results->expression_len,
			       c_results->expression );
	else
	    p2 += snprintf( p2, p2_end - p2,
			       " near \"%.*s\" in \"%.*s\"",
			       c_results->token_len, c_results->token,
			       c_results->expression_len,
			       c_results->expression );

	/* FIXME  if err_msg is too long, don't add in token */

	SPF_sanitize( spfcid, c_results->err_msg );
    }

    return comp_stat;
}


void SPF_init_c_results( SPF_c_results_t *c_results )
{
    memset( c_results, 0, sizeof( *c_results ) );
}


void SPF_reset_c_results( SPF_c_results_t *c_results )
{
    int		i;

    c_results->err = SPF_E_SUCCESS;
    if ( c_results->err_msg ) c_results->err_msg[0] = '\0';


    if ( c_results->err_msgs )
    {
	for( i = 0; i < c_results->num_errs; i++ )
	    if ( c_results->err_msgs[i] ) c_results->err_msgs[i][0] = '\0';
    }


    c_results->expression = NULL;
    c_results->expression_len = 0;
    c_results->token = NULL;
    c_results->token_len = 0;
    c_results->error_loc = NULL;
}


SPF_c_results_t SPF_dup_c_results( SPF_c_results_t c_results )
{
    SPF_c_results_t new_c_results;
    int		i;

    SPF_init_c_results( &new_c_results );


    if ( c_results.spfid )
	new_c_results.spfid = SPF_dup_id( c_results.spfid );
    new_c_results.err = c_results.err;
    if ( c_results.err_msg )
    {
	new_c_results.err_msg = strdup( c_results.err_msg );
	new_c_results.err_msg_len = strlen( c_results.err_msg );
    }

    if ( c_results.err_msgs )
    {
	new_c_results.num_errs = c_results.num_errs;
	new_c_results.err_msgs = malloc( c_results.num_errs * sizeof( c_results.err_msgs ) );

	if ( new_c_results.err_msgs )
	{
	    for( i = 0; i < c_results.num_errs; i++ )
		if ( c_results.err_msgs[i] )
		{
		    new_c_results.err_msgs[i] = strdup( c_results.err_msgs[i] );
		    new_c_results.err_msgs_len[i] = strlen( c_results.err_msgs[i] );
		}
	}

    }

    return new_c_results;
}


void SPF_free_c_results( SPF_c_results_t *c_results )
{
    int		i;

    if ( c_results->spfid ) SPF_destroy_id( c_results->spfid );
    if ( c_results->err_msg ) free( c_results->err_msg );

    if ( c_results->err_msgs )
    {
	for( i = 0; i < c_results->num_errs; i++ )
	    if ( c_results->err_msgs[i] ) free( c_results->err_msgs[i] );

	free( c_results->err_msgs );
    }

    SPF_init_c_results( c_results );
}



