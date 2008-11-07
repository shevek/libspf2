/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 * 
 *   a) The GNU Lesser General Public License as published by the Free
 *	  Software Foundation; either version 2.1, or (at your option) any
 *	  later version, 
 * 
 *   OR
 * 
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */

#include "spf_sys_config.h"



#ifdef STDC_HEADERS
# include <stdio.h>		/* stdin / stdout */
# include <stdlib.h>	   /* malloc / free */
# include <ctype.h>		/* isupper / tolower */
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>	   /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>	   /* strstr / strdup */
# endif
#endif


#include "spf.h"
#include "spf_internal.h"


static SPF_errcode_t
SPF_record_stringify_data(SPF_data_t *data, SPF_data_t *data_end,
						char **p_p, char *p_end,
						int is_mod, int cidr_ok, int debug )
{
	char		*p = *p_p;

	size_t		len;

	SPF_data_t		*cidr_data;

	if (debug)
		SPF_debugf(" string data: Building");

	if (p_end - p <= 0)
		return SPF_E_INTERNAL_ERROR;

	cidr_data = NULL;
	if ( data < data_end && data->dc.parm_type == PARM_CIDR )
	{
		if (debug)
			SPF_debugf(" string data: Found a CIDR at %p", data);
		if ( !cidr_ok )
			return SPF_E_INTERNAL_ERROR;

		cidr_data = data;
		data = SPF_data_next( data );
	}
		

	for( ; data < data_end; data = SPF_data_next( data ) )
	{
		if (debug)
			SPF_debugf(" string data: Handling data type %d at %p",
							data->ds.parm_type, data);
		if ( data->ds.parm_type == PARM_STRING )
		{
			char *s = SPF_data_str( data );
			char *s_end = s + data->ds.len;
			if (debug)
				SPF_debugf(" string data: String is [%d] '%*.*s'",
						data->ds.len, data->ds.len, data->ds.len, s);

			if (p_end - (p + data->ds.len) <= 0)
				return SPF_E_INTERNAL_ERROR;

			while (s < s_end) {
				if (*s == ' ') {
					*p++ = '%';
					*p++ = '_';
					s++;
				}
				else if (*s == '%') {
					*p++ = '%';
					s++;
					if (s[0] == '2' && s[1] == '0') {
						*p++ = '-';
						s += 2;
					}
					else {
						*p++ = '%';
						// *p++ = '%';
					}
				}
				else {
					*p++ = *s++;
				}
			}

			if (p_end - p <= 0)
				return SPF_E_INTERNAL_ERROR;
		}
		else if (data->dc.parm_type == PARM_CIDR) {
			/* Two CIDRs in a row is invalid. */
			return SPF_E_INVALID_CIDR;
		}
		else {
			len = snprintf( p, p_end - p, "%%{" );
			p += len;
			if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;


			if ( p_end - p <= 1 ) return SPF_E_INTERNAL_ERROR;
			switch( data->dv.parm_type )
			{
			case PARM_LP_FROM:				/* local-part of envelope-sender */
				*p = 'l';
				break;
					
			case PARM_ENV_FROM:				/* envelope-sender				*/
				*p = 's';
				break;
					
			case PARM_DP_FROM:				/* envelope-domain				*/
				*p = 'o';
				break;

			case PARM_CUR_DOM:				/* current-domain				*/
				*p = 'd';
				break;

			case PARM_CLIENT_IP:		/* SMTP client IP				*/
				*p = 'i';
				break;

			case PARM_CLIENT_IP_P:		/* SMTP client IP (pretty)		*/
				*p = 'c';
				break;

			case PARM_TIME:				/* time in UTC epoch secs		*/
				if ( !is_mod )
					return SPF_E_INVALID_VAR;
				*p = 't';
				break;

			case PARM_CLIENT_DOM:		/* SMTP client domain name		*/
				*p = 'p';
				break;

			case PARM_CLIENT_VER:		/* IP ver str - in-addr/ip6		*/
				*p = 'v';
				break;

			case PARM_HELO_DOM:				/* HELO/EHLO domain				*/
				*p = 'h';
				break;

			case PARM_REC_DOM:				/* receiving domain				*/
				*p = 'r';
				break;

			default:
				return SPF_E_INVALID_VAR;
				break;
			}
			if ( data->dv.url_encode )
				*p = toupper( *p );
			p++;
			if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
				

			if ( data->dv.num_rhs )
			{
				len = snprintf( p, p_end - p, "%d", data->dv.num_rhs );
				p += len;
				if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
			}
			
				
			if ( p_end - p <= 8 ) return SPF_E_INTERNAL_ERROR;
			if ( data->dv.rev )
				*p++ = 'r';

			if ( data->dv.delim_dot
				 && ( data->dv.delim_dash
					  || data->dv.delim_plus
					  || data->dv.delim_equal
					  || data->dv.delim_bar
					  || data->dv.delim_under
					 )
				)
				*p++ = '.';
			if ( data->dv.delim_dash )
				*p++ = '-';
			if ( data->dv.delim_plus )
				*p++ = '+';
			if ( data->dv.delim_equal )
				*p++ = '=';
			if ( data->dv.delim_bar )
				*p++ = '|';
			if ( data->dv.delim_under )
				*p++ = '_';

			*p++ = '}';
			if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
		}
	}

		
	if ( cidr_data )
	{
		if ( cidr_data->dc.ipv4 )
		{
			len = snprintf( p, p_end - p, "/%d", cidr_data->dc.ipv4 );
			p += len;
			if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
		}
			
		if ( cidr_data->dc.ipv6 )
		{
			len = snprintf( p, p_end - p, "//%d", cidr_data->dc.ipv6 );
			p += len;
			if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
		}
	}

	*p_p = p;
	return SPF_E_SUCCESS;
}


SPF_errcode_t
SPF_record_stringify( SPF_record_t *spf_record, char **bufp, size_t *buflenp)
{
	int				i;
	SPF_mech_t		*mech;
	SPF_mod_t		*mod;

	SPF_data_t		*data, *data_end;

	size_t		len;
	const char		*p_err;
	char		*p, *p_end;
	
	char		ip4_buf[ INET_ADDRSTRLEN ];
	char		ip6_buf[ INET6_ADDRSTRLEN ];

	int				cidr_ok;
	SPF_errcode_t	err;
	
#define debug spf_record->spf_server->debug

	SPF_ASSERT_NOTNULL(spf_record);

	/*
	 * make sure the return buffer is big enough
	 *
	 * The worse case for the version string:
	 *   "v=spf1 " = 6					= 4
	 * The worst cases for mechanisms
	 *   "ip4:111.222.333.444/31 " = 23   < 6 * 3.9
	 *   "ip6:<full-ipv6-spec>/126 " = 49 < 18 * 2.8
	 *   "-include:x " = 11			   = 5 * 2.2
	 *   "-all " = 5						  = 2 * 2.5
	 * 
	 * The worst case for modifiers:
	 *   "a=%{i15r.-+=|_} " = 16		  = 5 * 3.2
	 */
	
	len = sizeof( SPF_VER_STR )
		+ spf_record->mech_len * 4 + spf_record->mod_len * 4 /* data */
		+ sizeof( "\0" );
	
	err = SPF_recalloc(bufp, buflenp, len);
	if (err != SPF_E_SUCCESS)
		return err;

	p = *bufp;
	p_end = *bufp + *buflenp;

	if (debug)
		SPF_debugf("stringify: Buffer length is %lu\n", (unsigned long)*buflenp);


	/*
	 * generate SPF version string
	 */
	len = snprintf(p, p_end - p, "v=spf%d", spf_record->version);
	p += len;
	if (p_end - p <= 0)
		return SPF_E_INTERNAL_ERROR;
		

	/*
	 * generate mechanisms
	 */
	
	mech = spf_record->mech_first;
	for (i = 0; i < spf_record->num_mech; i++) {
		if (debug)
			SPF_debugf("stringify: Handling mechanism %d/%d at %p",
							i, spf_record->num_mech, mech);
		if ( p_end - p <= 1 ) return SPF_E_INTERNAL_ERROR;
		*p++ = ' ';
		

		if ( p_end - p <= 1 ) return SPF_E_INTERNAL_ERROR;
		switch( mech->prefix_type )
		{
		case PREFIX_PASS:
			/* *p++ = '+'; */
			break;
			
		case PREFIX_FAIL:
			*p++ = '-';
			break;
			
		case PREFIX_SOFTFAIL:
			*p++ = '~';
			break;
			
		case PREFIX_NEUTRAL:
			*p++ = '?';
			break;
			
		case PREFIX_UNKNOWN:
			return SPF_E_RESULT_UNKNOWN;
			break;

		default:
			return SPF_E_INVALID_PREFIX;
			break;
		}

		if (debug)
			SPF_debugf("Mechanism type is %d", mech->mech_type);

		switch( mech->mech_type )
		{
		case MECH_A:
			len = snprintf( p, p_end - p, "a" );
			break;
			
		case MECH_MX:
			len = snprintf( p, p_end - p, "mx" );
			break;
			
		case MECH_PTR:
			len = snprintf( p, p_end - p, "ptr" );
			break;
			
		case MECH_INCLUDE:
			len = snprintf( p, p_end - p, "include" );
			break;
			
		case MECH_IP4:
			p_err = inet_ntop( AF_INET, SPF_mech_ip4_data( mech ),
							 ip4_buf, sizeof( ip4_buf ) );
			if ( p_err == NULL )
				return SPF_E_INTERNAL_ERROR;
			if ( mech->mech_len )
				len = snprintf( p, p_end - p, "ip4:%s/%d",
									ip4_buf, mech->mech_len );
			else
				len = snprintf( p, p_end - p, "ip4:%s", ip4_buf );
			break;
			
		case MECH_IP6:
			p_err = inet_ntop( AF_INET6, SPF_mech_ip6_data( mech ),
							 ip6_buf, sizeof( ip6_buf ) );
			if ( p_err == NULL )
				return SPF_E_INTERNAL_ERROR;
			if ( mech->mech_len )
				len = snprintf( p, p_end - p, "ip6:%s/%d",
									ip6_buf, mech->mech_len );
			else
				len = snprintf( p, p_end - p, "ip6:%s", ip6_buf );
			break;
			
		case MECH_EXISTS:
			len = snprintf( p, p_end - p, "exists" );
			break;
			
		case MECH_ALL:
			len = snprintf( p, p_end - p, "all" );
			break;
			
		case MECH_REDIRECT:
			len = snprintf( p, p_end - p, "redirect" );
			break;

		default:
			return SPF_E_UNKNOWN_MECH;
			break;
		}
		p += len;
		if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;

		if (debug)
			SPF_debugf("stringify: Buffer so far is %s", p);

		if ( mech->mech_type != MECH_IP4  &&  mech->mech_type != MECH_IP6 )
		{
			data = SPF_mech_data( mech );
			data_end = SPF_mech_end_data( mech );
		
			if (SPF_mech_data_len(mech) > 0
				 /* We have an immediate string literal */
				 && (data->dc.parm_type != PARM_CIDR
					 /* Some data follows the CIDR */
					 || SPF_data_next( data ) < data_end)
				) {
				*p++ = ':';
			}

			cidr_ok = mech->mech_type == MECH_A || mech->mech_type == MECH_MX;
			err = SPF_record_stringify_data(
							data, data_end,
							&p, p_end,
							FALSE, cidr_ok, debug );

			if ( err != SPF_E_SUCCESS )
				return err;
		}
		
		mech = SPF_mech_next( mech );
	}


	/*
	 * generate modifiers
	 */

	mod = spf_record->mod_first;
	for( i = 0; i < spf_record->num_mod; i++ )
	{
		if (debug)
			SPF_debugf("stringify: Handling modifier %d/%d at %p",
							i, spf_record->num_mod, mod);
		if ( p_end - p <= 1 ) return SPF_E_INTERNAL_ERROR;
		*p++ = ' ';
		
		len = snprintf( p, p_end - p, "%.*s=",
							mod->name_len, SPF_mod_name( mod )  );
		p += len;
		if ( p_end - p <= 0 ) return SPF_E_INTERNAL_ERROR;
			
		data = SPF_mod_data( mod );
		data_end = SPF_mod_end_data( mod );
		
		err = SPF_record_stringify_data(
						data, data_end,
						&p, p_end,
						TRUE, TRUE, debug );

		if ( err != SPF_E_SUCCESS )
			return err;
		
		
		mod = SPF_mod_next( mod );
	}



	*p++ = '\0';

	return SPF_E_SUCCESS;
}
