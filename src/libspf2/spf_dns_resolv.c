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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

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

#ifdef HAVE_RESOLV_H
# include <resolv.h>       /* dn_skipname */
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_resolv.h"


typedef struct
{
    int		debug;
    SPF_dns_rr_t spfrr;
#if HAVE_DECL_RES_NINIT
    struct __res_state	res_state;
#endif
} SPF_dns_resolv_config_t; 

#if HAVE_DECL_RES_NINIT
#define SPF_h_errno spfhook->res_state.res_h_errno
#else
#define SPF_h_errno h_errno
#endif


static inline SPF_dns_resolv_config_t *SPF_voidp2spfhook( void *hook ) 
    { return (SPF_dns_resolv_config_t *)hook; }
static inline void *SPF_spfhook2voidp( SPF_dns_resolv_config_t *spfhook ) 
    { return (void *)spfhook; }



static SPF_dns_rr_t *SPF_dns_lookup_resolv( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_resolv_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    SPF_dns_rr_t *spfrr;

    int		err;
    int		i;
    int		nrec;
    int		cnt;

    u_char	response[2048];

    int		dns_len;
    
    ns_msg	ns_handle;
    ns_rr	rr;

    int		ns_sects[] = { ns_s_qd, ns_s_an, ns_s_ns, ns_s_ar }; 
    const char	*ns_sect_names[] = { "Question", "Answer", "Authority", "Additional" }; 
    int		ns_sect;
    int		num_ns_sect = sizeof( ns_sects ) / sizeof( *ns_sects );
    
    char	ip4_buf[ INET_ADDRSTRLEN ];
    char	ip6_buf[ INET6_ADDRSTRLEN ];
    char	name_buf[ NS_MAXDNAME ];
    int		prio;
    
    int		rdlen;
    const u_char	*rdata, *rdata_end;
    
    
    /*
     * initialize stuff
     */
    spfrr = &spfhook->spfrr;
    SPF_dns_reset_rr( spfrr );
    spfrr->herrno = NO_RECOVERY;
    spfrr->rr_type = rr_type;
    if ( domain && domain[0] != '\0' )
    {
	char   *new_domain;
	size_t new_len = strlen( domain ) + 1;

	if ( spfrr->domain_buf_len < new_len )
	{
	    new_domain = realloc( spfrr->domain, new_len );
	    if ( new_domain == NULL )
		return spfrr;

	    spfrr->domain = new_domain;
	    spfrr->domain_buf_len = new_len;
	}
	strcpy( spfrr->domain, domain );
    }
    else if ( spfrr->domain )
	spfrr->domain[0] = '\0';

    cnt = 0;
        
    if ( spfhook->debug )
	SPF_debugf( "DNS resolv looking for:  %s  %s (%d)",
		 domain,
		 ( (rr_type == ns_t_a)     ? "A" :
		   (rr_type == ns_t_aaaa)  ? "AAAA" :
		   (rr_type == ns_t_mx)    ? "MX" :
		   (rr_type == ns_t_txt)   ? "TXT" :
		   (rr_type == ns_t_ptr)   ? "PTR" :
		   (rr_type == ns_t_any)   ? "ANY" :
		   "??" ),
		 rr_type );

    
    /*
     * try resolving the name
     */
#if HAVE_DECL_RES_NINIT
    dns_len = res_nquery( &spfhook->res_state, domain, ns_c_in, rr_type,
			 response, sizeof( response ) );
#else
    dns_len = res_query( domain, ns_c_in, rr_type,
			 response, sizeof( response ) );
#endif

    if ( dns_len < 0 )
    {
	if ( spfhook->debug )
	    SPF_debugf( "query failed: err = %d  %s (%d)",
		    dns_len, hstrerror( SPF_h_errno ), SPF_h_errno );

	if ( spfrr->herrno == HOST_NOT_FOUND && spfdic->layer_below )
	    return SPF_dcid2spfdic( spfdic->layer_below )->lookup( spfdic->layer_below, domain, rr_type, should_cache );

	spfrr->herrno = SPF_h_errno;
	return spfrr;
    }
    else
	spfrr->herrno = NETDB_SUCCESS;
	
    
    err = ns_initparse( response, dns_len, &ns_handle );

    if ( err < 0 )			/* 0 or -1 */
    {
	if ( spfhook->debug )
	    SPF_debugf( "ns_initparse failed: err = %d  %s (%d)",
		    err, strerror( errno ), errno );
	return spfrr;
    }

    
    if ( spfhook->debug > 1 )
    {
	SPF_debugf( "msg id:             %d", ns_msg_id( ns_handle ));
	SPF_debugf( "ns_f_qr quest/resp: %d", ns_msg_getflag( ns_handle, ns_f_qr ));
	SPF_debugf( "ns_f_opcode:        %d", ns_msg_getflag( ns_handle, ns_f_opcode ));
	SPF_debugf( "ns_f_aa auth ans:   %d", ns_msg_getflag( ns_handle, ns_f_aa ));
	SPF_debugf( "ns_f_tc truncated:  %d", ns_msg_getflag( ns_handle, ns_f_tc ));
	SPF_debugf( "ns_f_rd rec desire: %d", ns_msg_getflag( ns_handle, ns_f_rd ));
	SPF_debugf( "ns_f_ra rec avail:  %d", ns_msg_getflag( ns_handle, ns_f_ra ));
	SPF_debugf( "ns_f_rcode:         %d", ns_msg_getflag( ns_handle, ns_f_rcode ));
    }
    

    /* FIXME  the error handling from here on is suspect at best */
    for( ns_sect = 0; ns_sect < num_ns_sect; ns_sect++ )
    {
	if ( ns_sects[ ns_sect ] != ns_s_an )
	    continue;

	nrec = ns_msg_count( ns_handle, ns_sects[ ns_sect ] );

	if ( spfhook->debug > 1 )
	    SPF_debugf( "%s:  %d", ns_sect_names[ns_sect], nrec );

	spfrr->num_rr = 0;
	cnt = 0;
	for( i = 0; i < nrec; i++ )
	{
	    err = ns_parserr( &ns_handle, ns_sects[ ns_sect ], i, &rr );
	    if ( err < 0 )		/* 0 or -1 */
	    {
		if ( spfhook->debug > 1 )
		    SPF_debugf( "ns_parserr failed: err = %d  %s (%d)",
			    err, strerror( errno ), errno );
		return spfrr;
	    }

	    rdlen = ns_rr_rdlen( rr );
	    if ( spfhook->debug > 1 )
		SPF_debugf( "name: %s  type: %d  class: %d  ttl: %d  rdlen: %d",
			ns_rr_name( rr ), ns_rr_type( rr ), ns_rr_class( rr ),
			ns_rr_ttl( rr ), rdlen );

	    if ( rdlen <= 0 )
		continue;
	    
	    rdata = ns_rr_rdata( rr );

	    if ( spfhook->debug > 1 )
	    {
		switch( ns_rr_type( rr ) )
		{
		case ns_t_a:
		    SPF_debugf( "A: %s",
			    inet_ntop( AF_INET, rdata,
				       ip4_buf, sizeof( ip4_buf ) ));
		    break;
		
		case ns_t_aaaa:
		    SPF_debugf( "AAAA: %s",
			    inet_ntop( AF_INET6, rdata,
			    ip6_buf, sizeof( ip6_buf ) ));
		    break;
		
		case ns_t_ns:
		    err = ns_name_uncompress( response,
					      response + sizeof( response ),
					      rdata,
					      name_buf, sizeof( name_buf ) );
		    if ( err < 0 )		/* 0 or -1 */
		    {
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    }
		    else
			SPF_debugf( "NS: %s", name_buf );
		    break;
		
		case ns_t_cname:
		    err = ns_name_uncompress( response,
					      response + sizeof( response ),
					      rdata,
					      name_buf, sizeof( name_buf ) );
		    if ( err < 0 )		/* 0 or -1 */
		    {
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    }
		    else
			SPF_debugf( "CNAME: %s", name_buf );
		    break;
		
		case ns_t_mx:
		    prio = ns_get16( rdata );
		    err = ns_name_uncompress( response,
					      response + sizeof( response ),
					      rdata + NS_INT16SZ,
					      name_buf, sizeof( name_buf ) );
		    if ( err < 0 )		/* 0 or -1 */
		    {
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    }
		    else
			SPF_debugf( "MX: %d %s", prio, name_buf );
		    break;
		
		case ns_t_txt:
		    rdata_end = rdata + rdlen;
		    SPF_debugf( "TXT: (%d) \"%.*s\"",
			    rdlen, rdlen-1, rdata+1 );
		    break;
		
		case ns_t_ptr:
		    err = ns_name_uncompress( response,
					      response + sizeof( response ),
					      rdata,
					      name_buf, sizeof( name_buf ) );
		    if ( err < 0 )		/* 0 or -1 */
		    {
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    }
		    else
			SPF_debugf( "PTR: %s", name_buf );
		    break;
		
		default:
		    SPF_debugf( "not parsed:  type: %d", ns_rr_type( rr ) );
		    break;
		}
	    }

	    if ( ns_sects[ ns_sect ] != ns_s_an  &&  spfhook->debug > 1 )
		continue;


	    if ( ns_rr_type( rr ) != spfrr->rr_type
		 && ns_rr_type( rr ) != ns_t_cname )
	    {
		SPF_debugf( "unexpected rr type: %d   expected: %d",
			ns_rr_type( rr ), rr_type );
		continue;
	    }

	    switch( ns_rr_type( rr ) )
	    {
	    case ns_t_a:
		if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
					    sizeof( spfrr->rr[cnt]->a ) ) != SPF_E_SUCCESS )
		    return spfrr;
		memmove( &spfrr->rr[cnt]->a, rdata, sizeof( spfrr->rr[cnt]->a ) );
		cnt++;
		break;
		
	    case ns_t_aaaa:
		if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
					    sizeof( spfrr->rr[cnt]->aaaa ) ) != SPF_E_SUCCESS )
		    return spfrr;
		memmove( &spfrr->rr[cnt]->aaaa, rdata, sizeof( spfrr->rr[cnt]->aaaa ) );

		cnt++;
		break;
		
	    case ns_t_ns:
		break;
		
	    case ns_t_cname:
		/* FIXME:  are CNAMEs always sent with the real RR? */
		break;
		
	    case ns_t_mx:
		err = ns_name_uncompress( response,
					  response + sizeof( response ),
					  rdata + NS_INT16SZ,
					  name_buf, sizeof( name_buf ) );
		if ( err < 0 )		/* 0 or -1 */
		{
		    if ( spfhook->debug > 1 )
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    return spfrr;
		}
		    
		if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
					    strlen( name_buf ) + 1 ) != SPF_E_SUCCESS )
		    return spfrr;
		strcpy( spfrr->rr[cnt]->mx, name_buf );

		cnt++;
		break;
		
	    case ns_t_txt:
		if ( rdlen > 1 )
		{
		    u_char *src, *dst;
		    size_t len;

		    if ( SPF_dns_rr_buf_malloc( spfrr, cnt, rdlen ) != SPF_E_SUCCESS )
			return spfrr;

		    dst = spfrr->rr[cnt]->txt;
		    len = 0;
		    src = (u_char *)rdata;
		    while ( rdlen > 0 )
		    {
			len = *src;
			src++;
			memcpy( dst, src, len );
			dst += len;
			src += len;
			rdlen -= len + 1;
		    }
		    *dst = '\0';
		} else {
		    if ( SPF_dns_rr_buf_malloc( spfrr, cnt, 1 ) != SPF_E_SUCCESS )
			return spfrr;
		    spfrr->rr[cnt]->txt[0] = '\0';
		}

		cnt++;
		break;
		
	    case ns_t_ptr:
		err = ns_name_uncompress( response,
					  response + sizeof( response ),
					  rdata,
					  name_buf, sizeof( name_buf ) );
		if ( err < 0 )		/* 0 or -1 */
		{
		    if ( spfhook->debug > 1 )
			SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		    return spfrr;
		}

		if ( SPF_dns_rr_buf_malloc( spfrr, cnt,
					    strlen( name_buf ) + 1 ) != SPF_E_SUCCESS )
		    return spfrr;
		strcpy( spfrr->rr[cnt]->ptr, name_buf );

		cnt++;
		break;
		
	    default:
		break;
	    }		    
	}

	spfrr->num_rr = cnt;
    }

    if ( spfrr->num_rr == 0 )
	spfhook->spfrr.herrno = NO_DATA;

    return spfrr;
}


SPF_dns_config_t SPF_dns_create_config_resolv( SPF_dns_config_t layer_below, int debug )
{
    SPF_dns_iconfig_t     *spfdic;
    SPF_dns_resolv_config_t *spfhook;

    
    spfdic = malloc( sizeof( *spfdic ) );
    if ( spfdic == NULL )
	return NULL;

    spfdic->hook = calloc( 1, sizeof( SPF_dns_resolv_config_t ) );
    if ( spfdic->hook == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfdic->destroy     = SPF_dns_destroy_config_resolv;
    spfdic->lookup      = SPF_dns_lookup_resolv;
    spfdic->get_spf     = NULL;
    spfdic->get_exp     = NULL;
    spfdic->add_cache   = NULL;
    spfdic->layer_below = layer_below;
    spfdic->name        = "resolv";
    
    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->debug = debug;
    SPF_dns_reset_rr( &spfhook->spfrr );
    spfhook->spfrr.source = SPF_spfdic2dcid( spfdic );

#if HAVE_DECL_RES_NINIT
    if ( res_ninit( &spfhook->res_state ) != 0 )
    {
	free( spfdic );
	return NULL;
    }
#else
    if ( res_init() != 0 )
    {
	free( spfdic );
	return NULL;
    }
#endif

    return SPF_spfdic2dcid( spfdic );
}

void SPF_dns_reset_config_resolv( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t    *spfdic = SPF_dcid2spfdic( spfdcid );


    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );


    SPF_dns_reset_rr( &(SPF_voidp2spfhook( spfdic->hook )->spfrr) );
}

void SPF_dns_destroy_config_resolv( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    if ( spfdic->hook )
    {
	SPF_dns_resolv_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );

	SPF_dns_destroy_rr_var( &spfhook->spfrr );

#if HAVE_DECL_RES_NINIT
	res_nclose( &spfhook->res_state );
#else
	res_close();
#endif
	
	free( spfdic->hook );
    }
    

    if ( spfdic )
	free( spfdic );
}


