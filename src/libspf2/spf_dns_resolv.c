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

/**
 * If we have a res_ninit then we make a thread-local resolver
 * state, which we use to perform all resolutions.
 *
 * If we do not have res_ninit, then we do a res_init() at
 * server-create time, and a res_close() at server-close time, and
 * we are NOT thread-safe. I think we don't actually have to call
 * res_init(), but we do anyway.
 */

#ifndef _WIN32

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

#ifdef HAVE_PTHREAD_H
# include <pthread.h>
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_resolv.h"


#if HAVE_DECL_RES_NINIT
# define SPF_h_errno res_state->res_h_errno
#else
# define SPF_h_errno h_errno
#endif

#ifdef HAVE_DECL_RES_NINIT
static pthread_once_t	res_state_control = PTHREAD_ONCE_INIT;
static pthread_key_t	res_state_key;

static void
SPF_dns_resolv_thread_term(void *arg)
{
	res_nclose( (struct __res_state *)arg );
	free(arg);
}

static void
SPF_dns_resolv_init_key()
{
	pthread_key_create(&res_state_key, SPF_dns_resolv_thread_term);
}
#endif

static SPF_dns_rr_t *
SPF_dns_resolv_lookup(SPF_dns_server_t *spf_dns_server,
				const char *domain, ns_type rr_type, int should_cache)
{
    SPF_dns_rr_t			*spfrr;

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

	void				*res_spec;
	struct __res_state	*res_state;

	SPF_ASSERT_NOTNULL(spf_dns_server);

#if HAVE_DECL_RES_NINIT
	/** Get the thread-local resolver state. */
	res_spec = pthread_getspecific(res_state_key);
	if (res_spec == NULL) {
		res_state = (struct __res_state *)
						malloc(sizeof(struct __res_state));
		memset(res_state, 0, sizeof(struct __res_state));
		if (res_ninit(res_state) != 0) {
			SPF_error("Failed to call res_ninit()");
		}
		pthread_setspecific(res_state_key, (void *)res_state);
	}
	else {
		res_state = (struct __res_state *)res_spec;
	}

	/* Resolve the name. */
	dns_len = res_nquery(res_state, domain, ns_c_in, rr_type,
			 response, sizeof(response));
#else
    dns_len = res_query(domain, ns_c_in, rr_type,
			 response, sizeof(response));
#endif

	if (dns_len < 0) {
		/* This block returns unconditionally. */
		if (spf_dns_server->debug)
			SPF_debugf("query failed: err = %d  %s (%d): %s",
				dns_len, hstrerror(SPF_h_errno), SPF_h_errno,
				domain);
		if ((SPF_h_errno == HOST_NOT_FOUND) &&
				(spf_dns_server->layer_below != NULL)) {
			return SPF_dns_lookup(spf_dns_server->layer_below,
							domain, rr_type, should_cache);
		}
		return SPF_dns_rr_new_init(spf_dns_server,
						domain, rr_type, 0, SPF_h_errno);
	}

    /*
     * initialize stuff
     */
	spfrr = SPF_dns_rr_new_init(spf_dns_server,
					domain, rr_type, 0, NETDB_SUCCESS);

    err = ns_initparse( response, dns_len, &ns_handle );

	if ( err < 0 ) {	/* 0 or -1 */
		if ( spf_dns_server->debug )
			SPF_debugf( "ns_initparse failed: err = %d  %s (%d)",
				err, strerror( errno ), errno );
		return spfrr;
    }


    if ( spf_dns_server->debug > 1 ) {
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
	for( ns_sect = 0; ns_sect < num_ns_sect; ns_sect++ ) {
		if ( ns_sects[ ns_sect ] != ns_s_an )
			continue;

		nrec = ns_msg_count( ns_handle, ns_sects[ ns_sect ] );

		if ( spf_dns_server->debug > 1 )
			SPF_debugf( "%s:  %d", ns_sect_names[ns_sect], nrec );

		spfrr->num_rr = 0;
		cnt = 0;
		for( i = 0; i < nrec; i++ ) {
			err = ns_parserr( &ns_handle, ns_sects[ ns_sect ], i, &rr );
			if ( err < 0 )		/* 0 or -1 */
			{
			if ( spf_dns_server->debug > 1 )
				SPF_debugf( "ns_parserr failed: err = %d  %s (%d)",
					err, strerror( errno ), errno );
			return spfrr;
			}

			rdlen = ns_rr_rdlen( rr );
			if ( spf_dns_server->debug > 1 )
			SPF_debugf( "name: %s  type: %d  class: %d  ttl: %d  rdlen: %d",
				ns_rr_name( rr ), ns_rr_type( rr ), ns_rr_class( rr ),
				ns_rr_ttl( rr ), rdlen );

			if ( rdlen <= 0 )
			continue;

			rdata = ns_rr_rdata( rr );

			if ( spf_dns_server->debug > 1 )
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

			if ( ns_sects[ ns_sect ] != ns_s_an  &&  spf_dns_server->debug > 1 )
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
			if ( SPF_dns_rr_buf_realloc( spfrr, cnt,
							sizeof( spfrr->rr[cnt]->a ) ) != SPF_E_SUCCESS )
				return spfrr;
			memmove( &spfrr->rr[cnt]->a, rdata, sizeof( spfrr->rr[cnt]->a ) );
			cnt++;
			break;

			case ns_t_aaaa:
			if ( SPF_dns_rr_buf_realloc( spfrr, cnt,
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
				if ( spf_dns_server->debug > 1 )
				SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
					err, strerror( errno ), errno );
				return spfrr;
			}

			if ( SPF_dns_rr_buf_realloc( spfrr, cnt,
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

				if ( SPF_dns_rr_buf_realloc( spfrr, cnt, rdlen ) != SPF_E_SUCCESS )
					return spfrr;

				dst = (u_char *)spfrr->rr[cnt]->txt;
				len = 0;
				src = (u_char *)rdata;
				while ( rdlen > 0 ) {
					len = *src;
					src++;
					memcpy( dst, src, len );
					dst += len;
					src += len;
					rdlen -= len + 1;
				}
				*dst = '\0';
			} else {
				if ( SPF_dns_rr_buf_realloc( spfrr, cnt, 1 ) != SPF_E_SUCCESS )
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
				if ( spf_dns_server->debug > 1 )
				SPF_debugf( "ns_name_uncompress failed: err = %d  %s (%d)",
					err, strerror( errno ), errno );
				return spfrr;
			}

			if ( SPF_dns_rr_buf_realloc( spfrr, cnt,
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
		spfrr->herrno = NO_DATA;

    return spfrr;
}


static void
SPF_dns_resolv_free(SPF_dns_server_t *spf_dns_server)
{
	SPF_ASSERT_NOTNULL(spf_dns_server);

#ifndef HAVE_DECL_RES_NINIT
	res_close();
#endif

	free(spf_dns_server);
}

SPF_dns_server_t *
SPF_dns_resolv_new(SPF_dns_server_t *layer_below,
				const char *name, int debug)
{
	SPF_dns_server_t		*spf_dns_server;

#if HAVE_DECL_RES_NINIT
	pthread_once(&res_state_control, SPF_dns_resolv_init_key);
#else
    if ( res_init() != 0 ) {
		perror("res_init");
		return NULL;
    }
#endif

    spf_dns_server = malloc(sizeof(SPF_dns_server_t));
    if (spf_dns_server == NULL)
		return NULL;
	memset(spf_dns_server, 0, sizeof(SPF_dns_server_t));

    if (name ==  NULL)
		name = "resolv";

    spf_dns_server->destroy     = SPF_dns_resolv_free;
    spf_dns_server->lookup      = SPF_dns_resolv_lookup;
    spf_dns_server->get_spf     = NULL;
    spf_dns_server->get_exp     = NULL;
    spf_dns_server->add_cache   = NULL;
    spf_dns_server->layer_below = layer_below;
    spf_dns_server->name        = name;
    spf_dns_server->debug       = debug;

    return spf_dns_server;
}

#endif	/* _WIN32 */
