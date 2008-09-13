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

#ifdef _WIN32

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

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_windns.h"
#pragma comment(lib, "dnsapi.lib")
#include <windns.h>


typedef struct
{
    int		debug;
    SPF_dns_rr_t spfrr;
} SPF_dns_windns_config_t; 


#define SPF_h_errno WSAGetLastError()


static inline SPF_dns_windns_config_t *SPF_voidp2spfhook( void *hook ) 
    { return (SPF_dns_windns_config_t *)hook; }
static inline void *SPF_spfhook2voidp( SPF_dns_windns_config_t *spfhook ) 
    { return (void *)spfhook; }


LPSTR SPF_dns_create_error_message_windns(DWORD last_error)
{
	LPSTR error_message;

	if (!FormatMessageA( 
		(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS),
		NULL,
		last_error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPSTR) &error_message,
        0,
        NULL))
	{
		return NULL;
	}

	return error_message;
}


void SPF_dns_destroy_error_message_windns(LPSTR error_message)
{
	LocalFree( error_message );
}


size_t SPF_dns_txt_get_length_windns(DWORD count, PSTR strings[])
{
	size_t	length;
	DWORD	i;

	length = 0;

	for( i = 0; i < count; i++ )
	{
		length = length + strlen(strings[i]);
	}

	return length;
}


char *SPF_dns_txt_concat_windns(char *buffer, DWORD count, PSTR strings[])
{
	DWORD	i;

	buffer[0] = 0;

	for( i = 0; i < count; i++ )
	{
		if ( strcat( buffer, strings[i] ) == NULL )
			return NULL;
	}

	return buffer;
}


static SPF_dns_rr_t *SPF_dns_lookup_windns( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_windns_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );
    SPF_dns_rr_t *spfrr;

    int		cnt;

	PDNS_RECORDA pDnsRecord;

    DNS_STATUS	status;
	LPSTR	error_message;
    
    char	ip4_buf[ INET_ADDRSTRLEN ];
    char	ip6_buf[ INET6_ADDRSTRLEN ];
    
    int		rdlen;

	DNS_A_DATA		*pA_data;
	DNS_AAAA_DATA	*pAAAA_data;
	DNS_MX_DATAA	*pMX_data;
	DNS_TXT_DATAA	*pTXT_data;
	DNS_PTR_DATAA	*pPTR_data;

	size_t	txt_data_len;
	char	*txt_concat;
 
    
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
		SPF_debugf( "WinDNS looking for:  %s  %s (%d)",
			domain,
			(
				(rr_type == ns_t_a)     ? "A" :
				(rr_type == ns_t_aaaa)  ? "AAAA" :
				(rr_type == ns_t_mx)    ? "MX" :
				(rr_type == ns_t_txt)   ? "TXT" :
				(rr_type == ns_t_ptr)   ? "PTR" :
				(rr_type == ns_t_any)   ? "ANY" :
				"??" 
			),
			rr_type );

    
    /*
     * try resolving the name
     */
    status = DnsQuery_A( domain, rr_type, 
                (DNS_QUERY_STANDARD + DNS_QUERY_TREAT_AS_FQDN), 
                NULL, &pDnsRecord, NULL );

    if ( status != DNS_RCODE_NOERROR )
    {
		if ( spfhook->debug )
		{
			error_message = SPF_dns_create_error_message_windns(SPF_h_errno);

			SPF_debugf( "query failed: err = %d  %s (%d)",
				status, error_message, SPF_h_errno );

			SPF_dns_destroy_error_message_windns(error_message);
		}

		if ( 
			( SPF_h_errno == HOST_NOT_FOUND ) && 
			( spfdic->layer_below )
			)
			return SPF_dcid2spfdic( spfdic->layer_below )->lookup( spfdic->layer_below, domain, rr_type, should_cache );

		spfrr->herrno = SPF_h_errno;
		return spfrr;
    }
    else
		spfrr->herrno = NETDB_SUCCESS;

	while (pDnsRecord)
	{
	    rdlen = pDnsRecord->wDataLength;

		if ( spfhook->debug > 1 )
			SPF_debugf( "name: %s  type: %d  ttl: %d  rdlen: %d",
				pDnsRecord->pName, pDnsRecord->wType,
				pDnsRecord->dwTtl, rdlen );

	    if ( rdlen <= 0 )
		{
			pDnsRecord = pDnsRecord->pNext;
			continue;
		}

		/* No sense in doing this twice */
		if (pDnsRecord->wType == ns_t_txt)
		{
			pTXT_data = &pDnsRecord->Data.TXT;

			txt_data_len = 
				SPF_dns_txt_get_length_windns( 
					pTXT_data->dwStringCount, 
					pTXT_data->pStringArray 
					);
		}

	    if ( spfhook->debug > 1 )
	    {
		switch( pDnsRecord->wType )
		{
		case ns_t_a:

			pA_data = &pDnsRecord->Data.A;

		    SPF_debugf( "A: %s",
			    inet_ntop( AF_INET, &pA_data->IpAddress,
				       ip4_buf, sizeof( ip4_buf ) ));
		    break;
		
		case ns_t_aaaa:

			pAAAA_data = &pDnsRecord->Data.AAAA;

		    SPF_debugf( "AAAA: %s",
			    inet_ntop( AF_INET6, &pAAAA_data->Ip6Address,
			    ip6_buf, sizeof( ip6_buf ) ));
		    break;
		
		case ns_t_ns:

			SPF_debugf( "NS: %s", pDnsRecord->Data.NS.pNameHost );
		    break;
		
		case ns_t_cname:

			SPF_debugf( "CNAME: %s", pDnsRecord->Data.CNAME.pNameHost );
		    break;

		case ns_t_mx:

			pMX_data = &pDnsRecord->Data.MX;

			SPF_debugf( "MX: %d %s", 
				pMX_data->wPreference, pMX_data->pNameExchange );
		    break;
		
		case ns_t_txt:

			txt_concat = malloc(txt_data_len + 1);

			if ( txt_concat == NULL )
				SPF_debugf( "TXT: (%d) - no memory for concatination",
					txt_data_len );
			else
			{
				if ( SPF_dns_txt_concat_windns(
						txt_concat, 
						pTXT_data->dwStringCount, 
						pTXT_data->pStringArray
						) == NULL )
					SPF_debugf( "TXT: (%d) - error in concatination",
						txt_data_len );
				else
				{
					SPF_debugf( "TXT: (%d) \"%s\"",
						txt_data_len, txt_concat );
				}
				free( txt_concat );
			}
		    break;
		
		case ns_t_ptr:

			pPTR_data = &pDnsRecord->Data.PTR;

			SPF_debugf( "PTR: %s", pPTR_data->pNameHost );
		    break;
		
		default:
		    SPF_debugf( "not parsed:  type: %d", pDnsRecord->wType );
		    break;
		}
		}

		if ( 
			( pDnsRecord->Flags.S.Section != DNSREC_ANSWER ) && 
			( spfhook->debug > 1 ) 
			)
		{
			pDnsRecord = pDnsRecord->pNext;
			continue;
		}
		

	    if (
			( pDnsRecord->wType != spfrr->rr_type ) && 
			( pDnsRecord->wType != ns_t_cname )
			)
	    {
			SPF_debugf( "unexpected rr type: %d   expected: %d",
				pDnsRecord->wType, rr_type );
			pDnsRecord = pDnsRecord->pNext;
			continue;
	    }

	    switch( pDnsRecord->wType )
	    {
	    case ns_t_a:

			pA_data = &pDnsRecord->Data.A;

			if ( SPF_dns_rr_buf_malloc(
				spfrr, cnt,	sizeof( pA_data->IpAddress ) 
				) != SPF_E_SUCCESS )
				return spfrr;
            
			memmove( &spfrr->rr[cnt]->a, &pA_data->IpAddress, 
				sizeof( pA_data->IpAddress ) );

			cnt++;
			break;
		
		case ns_t_aaaa:

			pAAAA_data = &pDnsRecord->Data.AAAA;

			if ( SPF_dns_rr_buf_malloc( 
				spfrr, cnt, sizeof( pAAAA_data->Ip6Address ) 
				) != SPF_E_SUCCESS )
				return spfrr;
            
			memmove( &spfrr->rr[cnt]->aaaa, &pAAAA_data->Ip6Address, 
				sizeof( pAAAA_data->Ip6Address ) );

			cnt++;
			break;

	    case ns_t_ns:
			break;

	    case ns_t_cname:
			/* FIXME:  are CNAMEs always sent with the real RR? */
			break;
		
	    case ns_t_mx:

			pMX_data = &pDnsRecord->Data.MX;

			if ( SPF_dns_rr_buf_malloc(
				spfrr, cnt,	strlen( pMX_data->pNameExchange ) + 1 
				) != SPF_E_SUCCESS )
				return spfrr;

			strcpy( spfrr->rr[cnt]->mx, pMX_data->pNameExchange );

			cnt++;
			break;
		
	    case ns_t_txt:

			if ( SPF_dns_rr_buf_malloc( 
					spfrr, cnt, txt_data_len + 1 
					) != SPF_E_SUCCESS )
				return spfrr;

			if ( SPF_dns_txt_concat_windns(
					spfrr->rr[cnt]->txt, 
					pTXT_data->dwStringCount, 
					pTXT_data->pStringArray
					) == NULL )
				return spfrr;

			cnt++;
			break;
		
	    case ns_t_ptr:

			pPTR_data = &pDnsRecord->Data.PTR;

			if ( SPF_dns_rr_buf_malloc(
				spfrr, cnt,	strlen( pPTR_data->pNameHost ) + 1 
				) != SPF_E_SUCCESS )
				return spfrr;

			strcpy( spfrr->rr[cnt]->ptr, pPTR_data->pNameHost );

			cnt++;
			break;
		
	    default:
			break;
		}
        
		spfrr->num_rr = cnt;

		pDnsRecord = pDnsRecord->pNext;
	}

    if ( spfrr->num_rr == 0 )
		spfhook->spfrr.herrno = NO_DATA;

    return spfrr;
}


SPF_dns_config_t SPF_dns_create_config_windns( SPF_dns_config_t layer_below, int debug )
{
    SPF_dns_iconfig_t     *spfdic;
    SPF_dns_windns_config_t *spfhook;

    
    spfdic = malloc( sizeof( *spfdic ) );
    if ( spfdic == NULL )
	return NULL;

    spfdic->hook = calloc( 1, sizeof( SPF_dns_windns_config_t ) );
    if ( spfdic->hook == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfdic->destroy     = SPF_dns_destroy_config_windns;
    spfdic->lookup      = SPF_dns_lookup_windns;
    spfdic->get_spf     = NULL;
    spfdic->get_exp     = NULL;
    spfdic->add_cache   = NULL;
    spfdic->layer_below = layer_below;
    spfdic->name        = "windns";
    
    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->debug = debug;
    SPF_dns_reset_rr( &spfhook->spfrr );
    spfhook->spfrr.source = SPF_spfdic2dcid( spfdic );

    return SPF_spfdic2dcid( spfdic );
}

void SPF_dns_reset_config_windns( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t    *spfdic = SPF_dcid2spfdic( spfdcid );


    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );


    SPF_dns_reset_rr( &(SPF_voidp2spfhook( spfdic->hook )->spfrr) );
}

void SPF_dns_destroy_config_windns( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    if ( spfdic->hook )
    {
	SPF_dns_windns_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );

	SPF_dns_destroy_rr_var( &spfhook->spfrr );

	free( spfdic->hook );
    }

    if ( spfdic )
	free( spfdic );
}

#endif
