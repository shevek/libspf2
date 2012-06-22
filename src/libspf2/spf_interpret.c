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
#endif

#ifdef HAVE_STRING_H
# include <string.h>	   /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>	   /* strstr / strdup */
# endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <ctype.h>

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_server.h"

static SPF_errcode_t
SPF_i_set_explanation(SPF_response_t *spf_response)
{
	SPF_server_t	*spf_server;
	SPF_request_t	*spf_request;
	SPF_record_t	*spf_record;
	SPF_errcode_t	 err;
	char			*buf;
	size_t			 buflen;

	SPF_ASSERT_NOTNULL(spf_response);
	spf_request = spf_response->spf_request;
	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	spf_record = spf_response->spf_record_exp;
	SPF_ASSERT_NOTNULL(spf_record);

	if (spf_response->explanation)
		free(spf_response->explanation);
	spf_response->explanation = NULL;

	buflen = SPF_SMTP_COMMENT_SIZE + 1;
	buf = malloc(buflen);
	if (buf == NULL)
		return SPF_E_NO_MEMORY;
	memset(buf, '\0', buflen);

	err = SPF_request_get_exp(spf_server, spf_request,
					spf_response, spf_record, &buf, &buflen);
	if (err != SPF_E_SUCCESS) {
		free(buf);
		return err;
	}

	spf_response->explanation = buf;

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_i_set_smtp_comment(SPF_response_t *spf_response)
{
	SPF_server_t	*spf_server;
	SPF_request_t	*spf_request;
	SPF_errcode_t	 err;
	char			 buf[SPF_SMTP_COMMENT_SIZE];

	SPF_ASSERT_NOTNULL(spf_response);
	spf_request = spf_response->spf_request;
	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	if (spf_response->smtp_comment)
		free(spf_response->smtp_comment);
	spf_response->smtp_comment = NULL;

	/* smtp_comment = exp= + <why string> */
	switch (spf_response->result) {
		case SPF_RESULT_FAIL:
		case SPF_RESULT_SOFTFAIL:
		case SPF_RESULT_NEUTRAL:

			err = SPF_i_set_explanation(spf_response);
			if (err != SPF_E_SUCCESS)
				return err;

			memset(buf, '\0', sizeof(buf));
			snprintf(buf, SPF_SMTP_COMMENT_SIZE, "%s : Reason: %s",
					spf_response->explanation,
					SPF_strreason(spf_response->reason));
			buf[SPF_SMTP_COMMENT_SIZE - 1] = '\0';

			/* It doesn't really hurt much if this fails. */
			spf_response->smtp_comment = strdup(buf);
			if (! spf_response->smtp_comment)
				return SPF_E_NO_MEMORY;

			break;
		case SPF_RESULT_INVALID:
		case SPF_RESULT_PASS:
		case SPF_RESULT_TEMPERROR:
		case SPF_RESULT_PERMERROR:
		case SPF_RESULT_NONE:
		default:
			break;
	}

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_i_set_header_comment(SPF_response_t *spf_response)
{
	SPF_server_t	*spf_server;
	SPF_request_t	*spf_request;
	char			*spf_source;

	size_t			 len;

	char			 ip4_buf[ INET_ADDRSTRLEN ];
	char			 ip6_buf[ INET6_ADDRSTRLEN ];
	const char		*ip;

	char			*buf;
	char			*sender_dom;
	char			*p, *p_end;

	SPF_ASSERT_NOTNULL(spf_response);
	spf_request = spf_response->spf_request;
	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	if (spf_response->header_comment)
		free(spf_response->header_comment);
	spf_response->header_comment = NULL;

	/* Is this cur_dom? */
	sender_dom = spf_request->env_from_dp;
	if (sender_dom == NULL)
		sender_dom = spf_request->helo_dom;

	if ( spf_response->reason == SPF_REASON_LOCAL_POLICY ) {
		spf_source = strdup( "local policy" );
	}
	else if ( spf_response->reason == SPF_REASON_2MX ) {
		if ( spf_request->rcpt_to_dom == NULL  || spf_request->rcpt_to_dom[0] == '\0' )
			SPF_error( "RCPT TO domain is NULL" );

		spf_source = strdup( spf_request->rcpt_to_dom );
	}
	else if ( sender_dom == NULL ) {
		spf_source = strdup( "unknown domain" );
	}
	else {
		len = strlen( sender_dom ) + sizeof( "domain of " );
		spf_source = malloc( len );
		if ( spf_source )
			snprintf( spf_source, len, "domain of %s", sender_dom );
	}

	if ( spf_source == NULL )
		return SPF_E_INTERNAL_ERROR;

	ip = NULL;
	if ( spf_request->client_ver == AF_INET ) {
		ip = inet_ntop( AF_INET, &spf_request->ipv4,
						ip4_buf, sizeof( ip4_buf ) );
	}
	else if (spf_request->client_ver == AF_INET6 ) {
		ip = inet_ntop( AF_INET6, &spf_request->ipv6,
						ip6_buf, sizeof( ip6_buf ) );
	}
	if ( ip == NULL )
		ip = "(unknown ip address)";

	len = strlen( SPF_request_get_rec_dom(spf_request) ) + strlen( spf_source ) + strlen( ip ) + 80;
	buf = malloc( len );
	if ( buf == NULL ) {
		free( spf_source );
		return SPF_E_INTERNAL_ERROR;
	}

	p = buf;
	p_end = p + len;

	/* create the stock header comment */
	p += snprintf( p, p_end - p, "%s: ",  SPF_request_get_rec_dom(spf_request) );

	switch(spf_response->result)
	{
	case SPF_RESULT_PASS:
		if ( spf_response->reason == SPF_REASON_LOCALHOST )
			snprintf( p, p_end - p, "localhost is always allowed." );
		else if ( spf_response->reason == SPF_REASON_2MX )
			snprintf( p, p_end - p, "message received from %s which is an MX secondary for %s.",
					  ip, spf_source );
		else
			snprintf( p, p_end - p, "%s designates %s as permitted sender",
					  spf_source, ip );
		break;

	case SPF_RESULT_FAIL:
		snprintf( p, p_end - p, "%s does not designate %s as permitted sender",
				  spf_source, ip );
		break;

	case SPF_RESULT_SOFTFAIL:
		snprintf( p, p_end - p, "transitioning %s does not designate %s as permitted sender",
				  spf_source, ip );
		break;

	case SPF_RESULT_PERMERROR:
		snprintf(p, p_end - p, "error in processing during lookup of %s: %s",
					  spf_source, SPF_strerror(spf_response->err));
		break;

	case SPF_RESULT_NEUTRAL:
		snprintf(p, p_end - p, "%s is neither permitted nor denied by %s",
				ip, spf_source);
		break;
	case SPF_RESULT_NONE:
		snprintf(p, p_end - p, "%s does not provide an SPF record",
				spf_source);
		break;

	case SPF_RESULT_TEMPERROR:
		snprintf(p, p_end - p, "encountered temporary error during SPF processing of %s",
				spf_source );
		break;


	default:
		snprintf( p, p_end - p, "error: unknown SPF result %d encountered while checking %s for %s",
				  spf_response->result, ip, spf_source );
		break;
	}

	if (spf_source)
		free(spf_source);

	spf_response->header_comment = SPF_sanitize(spf_server, buf);

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_i_set_received_spf(SPF_response_t *spf_response)
{
	SPF_server_t	*spf_server;
	SPF_request_t	*spf_request;
	char			 ip4_buf[ INET_ADDRSTRLEN ];
	char			 ip6_buf[ INET6_ADDRSTRLEN ];
	const char		*ip;

	char			*buf;
	size_t			 buflen = SPF_RECEIVED_SPF_SIZE;
	char			*buf_value;
	
	char			*p, *p_end;

	SPF_ASSERT_NOTNULL(spf_response);
	spf_request = spf_response->spf_request;
	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	if (spf_response->received_spf)
		free(spf_response->received_spf);
	spf_response->received_spf = NULL;

	buf = malloc( buflen );
	if ( buf == NULL )
		return SPF_E_INTERNAL_ERROR;
	
	p = buf;
	p_end = p + buflen;

	/* create the stock Received-SPF: header */

	p += snprintf( p, p_end - p, "Received-SPF: ");
	buf_value = p;

	do {	/* A prop for a structured goto called 'break' */
		p += snprintf( p, p_end - p, "%s (%s)",
					   SPF_strresult( spf_response->result ),
					   spf_response->header_comment );
		if ( p_end - p <= 0 ) break;

		
		
		/* add in the optional ip address keyword */
		ip = NULL;
		if ( spf_request->client_ver == AF_INET ) {
			ip = inet_ntop( AF_INET, &spf_request->ipv4,
							ip4_buf, sizeof( ip4_buf ) );
		}
		else if (spf_request->client_ver == AF_INET6 ) {
			ip = inet_ntop( AF_INET6, &spf_request->ipv6,
							ip6_buf, sizeof( ip6_buf ) );
		}

		if ( ip != NULL ) {
			p += snprintf( p, p_end - p, " client-ip=%s;", ip );
			if ( p_end - p <= 0 ) break;
		}
		

		/* add in the optional envelope-from keyword */
		if ( spf_request->env_from != NULL ) {
			p += snprintf( p, p_end - p, " envelope-from=%s;", spf_request->env_from );
			if ( p_end - p <= 0 ) break;
		}
		

		/* add in the optional helo domain keyword */
		if ( spf_request->helo_dom != NULL ) {
			p += snprintf( p, p_end - p, " helo=%s;", spf_request->helo_dom );
			if ( p_end - p <= 0 ) break;
		}
		

		/* FIXME: Add in full compiler errors. */
#if 0
		/* add in the optional compiler error keyword */
		if ( output.err_msg != NULL ) {
			p += snprintf( p, p_end - p, " problem=%s;", output.err_msg );
			if ( p_end - p <= 0 ) break;
		}
		else if ( c_results.err_msg != NULL ) {
			p += snprintf( p, p_end - p, " problem=%s;", c_results.err_msg );
			if ( p_end - p <= 0 ) break;
		}
#endif

		/* FIXME  should the explanation string be included in the header? */

		/* FIXME  should the header be reformated to include line breaks? */
	} while(0);

	spf_response->received_spf = SPF_sanitize(spf_server, buf);
	spf_response->received_spf_value = buf_value;

	return SPF_E_SUCCESS;
}



#define DONE(result,reason,err) SPF_i_done(spf_response, result, reason, err)
#define DONE_TEMPERR(err) DONE(SPF_RESULT_TEMPERROR,SPF_REASON_NONE,err)
#define DONE_PERMERR(err) DONE(SPF_RESULT_PERMERROR,SPF_REASON_NONE,err)
#define DONE_MECH(result) DONE(result, SPF_REASON_MECH, SPF_E_SUCCESS)

/**
 * This must be called with EITHER
 * spf_response->spf_record_exp != NULL
 *   OR
 * result in { SPF_RESULT_PASS SPF_RESULT_INVALID
 *		SPF_RESULT_TEMPERROR SPF_RESULT_PERMERROR }
 * or the library will abort when it tries to generate an explanation.
 */
SPF_errcode_t
SPF_i_done(SPF_response_t *spf_response,
	SPF_result_t result, SPF_reason_t reason, SPF_errcode_t err)
{
	SPF_request_t	*spf_request;
	SPF_server_t	*spf_server;

	SPF_ASSERT_NOTNULL(spf_response);
	spf_request = spf_response->spf_request;
	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	spf_response->result = result;
	spf_response->reason = reason;
	spf_response->err = err;

	SPF_i_set_smtp_comment(spf_response);
	SPF_i_set_header_comment(spf_response);
	SPF_i_set_received_spf(spf_response);

	return err;
}

/*
 * FIXME: Everything before this line could go into a separate file.
 */




#define INET_NTOP(af, src, dst, cnt) do { \
	if (inet_ntop(af, src, dst, cnt) == NULL) \
		snprintf(dst, cnt, "ip-error" ); \
			} while(0)

static int
SPF_i_mech_cidr(SPF_request_t *spf_request, SPF_mech_t *mech)
{
	SPF_data_t				*data;

	SPF_ASSERT_NOTNULL(mech);

	switch( mech->mech_type )
	{
	case MECH_IP4:
	case MECH_IP6:
		return mech->mech_len;
		break;

	case MECH_A:
	case MECH_MX:
		data = SPF_mech_data( mech );
		/* XXX this was <= but I think that was wrong. */
		if ( data < SPF_mech_end_data( mech )
			 && data->dc.parm_type == PARM_CIDR )
		{
			if ( spf_request->client_ver == AF_INET )
				return data->dc.ipv4;
			else if ( spf_request->client_ver == AF_INET6 )
				return data->dc.ipv6;
		}
		break;
	}

	return 0;
}



static int
SPF_i_match_ip4(SPF_server_t *spf_server,
			SPF_request_t *spf_request,
			SPF_mech_t *mech,
			struct in_addr ipv4 )
{
	char		src_ip4_buf[ INET_ADDRSTRLEN ];
	char		dst_ip4_buf[ INET_ADDRSTRLEN ];
	char		mask_ip4_buf[ INET_ADDRSTRLEN ];

	struct in_addr		src_ipv4;
	int				cidr, mask;


	if ( spf_request->client_ver != AF_INET )
		return FALSE;

	src_ipv4 = spf_request->ipv4;

	cidr = SPF_i_mech_cidr( spf_request, mech );
	if ( cidr == 0 )
		cidr = 32;
	mask = 0xffffffff << (32 - cidr);
	mask = htonl(mask);

	if (spf_server->debug) {
		INET_NTOP(AF_INET, &src_ipv4.s_addr,
						src_ip4_buf, sizeof(src_ip4_buf));
		INET_NTOP(AF_INET, &ipv4.s_addr,
						dst_ip4_buf, sizeof(dst_ip4_buf));
		INET_NTOP(AF_INET, &mask,
						mask_ip4_buf, sizeof(mask_ip4_buf));
		SPF_debugf( "ip_match:  %s == %s  (/%d %s):  %d",
				src_ip4_buf, dst_ip4_buf, cidr, mask_ip4_buf,
				(src_ipv4.s_addr & mask) == (ipv4.s_addr & mask));
	}

	return (src_ipv4.s_addr & mask) == (ipv4.s_addr & mask);
}


static int
SPF_i_match_ip6(SPF_server_t *spf_server,
			SPF_request_t *spf_request,
			SPF_mech_t *mech,
			struct in6_addr ipv6 )
{
	char		src_ip6_buf[ INET6_ADDRSTRLEN ];
	char		dst_ip6_buf[ INET6_ADDRSTRLEN ];

	struct in6_addr		src_ipv6;
	int				cidr, cidr_save, mask;
	int				i;
	int				match;

	if ( spf_request->client_ver != AF_INET6 )
		return FALSE;

	src_ipv6 = spf_request->ipv6;

	cidr = SPF_i_mech_cidr(spf_request, mech);
	if ( cidr == 0 )
		cidr = 128;
	cidr_save = cidr;

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

	if (spf_server->debug) {
		INET_NTOP(AF_INET6, &src_ipv6.s6_addr,
							src_ip6_buf, sizeof(src_ip6_buf));
		INET_NTOP(AF_INET6, &ipv6.s6_addr,
							dst_ip6_buf, sizeof(dst_ip6_buf));
		SPF_debugf( "ip_match:  %s == %s  (/%d):  %d",
				src_ip6_buf, dst_ip6_buf, cidr_save, match );
	}

	return match;
}

static int
SPF_i_match_domain(SPF_server_t *spf_server,
				const char *hostname, const char *domain)
{
	const char	*hp;
	size_t		 hlen;
	size_t		 dlen;

	if (spf_server->debug)
		SPF_debugf( "%s ?=? %s", hostname, domain );

	hlen = strlen(hostname);
	dlen = strlen(domain);

	/* A host cannot be a member of a domain longer than it is. */
	if (dlen > hlen)
		return 0;

	/* The two may be equal? */
	if (dlen == hlen)
		return (strcasecmp(hostname, domain) == 0);

	/* The domain may match a trailing portion preceded by a dot. */
	hp = hostname + (hlen - dlen);

	if (*(hp - 1) != '.')
		return 0;

	return (strcasecmp(hp, domain) == 0);
}


/*
 * Set cur_dom (to either sender or or helo_dom) before calling this.
 */

SPF_errcode_t
SPF_record_interpret(SPF_record_t *spf_record,
			SPF_request_t *spf_request, SPF_response_t *spf_response,
			int depth)
{
	SPF_server_t	*spf_server;

	/* Temporaries */
	int				 i, j;
	int				 m;			/* Mechanism iterator */
	SPF_mech_t		*mech;
	SPF_data_t		*data;
	SPF_data_t		*data_end;	/* XXX Replace with size_t data_len */

	/* Where to insert the local policy (whitelist) */
	SPF_mech_t		*local_policy;	/* Not the local policy */
	int				 found_all;		/* A crappy temporary. */

	char			*buf = NULL;
	size_t			 buf_len = 0;
	ns_type			 fetch_ns_type;
	const char		*lookup;

	SPF_dns_rr_t	*rr_a;
	SPF_dns_rr_t	*rr_aaaa;
	SPF_dns_rr_t	*rr_ptr;
	SPF_dns_rr_t	*rr_mx;

	SPF_errcode_t	 err;

	SPF_dns_server_t*resolver;

	/* An SPF record for subrequests - replaces c_results */
	SPF_record_t	*spf_record_subr;

	SPF_response_t	*save_spf_response;
	SPF_response_t	*spf_response_subr;
	const char		*save_cur_dom;

	struct in_addr	addr4;
	struct in6_addr addr6;

	int				max_ptr;
	int				max_mx;
	int				max_exceeded;

	char			 ip4_buf[ INET_ADDRSTRLEN ];
	char			 ip6_buf[ INET6_ADDRSTRLEN ];


	/*
	 * make sure we were passed valid data to work with
	 */
	SPF_ASSERT_NOTNULL(spf_record);
	SPF_ASSERT_NOTNULL(spf_request);
	SPF_ASSERT_NOTNULL(spf_response);
	spf_server = spf_record->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	SPF_ASSERT_NOTNULL(spf_response->spf_record_exp);

	if (depth > 20)
		return DONE_PERMERR(SPF_E_RECURSIVE);

	if ( spf_request->client_ver != AF_INET && spf_request->client_ver != AF_INET6 )
		return DONE_PERMERR(SPF_E_NOT_CONFIG);

	if (spf_request->cur_dom == NULL)
		return DONE_PERMERR(SPF_E_NOT_CONFIG);


	/*
	 * localhost always gets a free ride
	 */

#if 0
	/* This should have been done already before we got here. */
	if ( SPF_request_is_loopback( spf_request ) )
		return DONE(SPF_RESULT_PASS,SPF_REASON_LOCALHOST,SPF_E_SUCCESS);
#endif

	/*
	 * Do some start up stuff if we haven't recursed yet
	 */

	local_policy = NULL;

	if ( spf_request->use_local_policy ) {
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

		if ( spf_server->local_policy ) {
			mech = spf_record->mech_first;

			found_all = FALSE;
			for(m = 0; m < spf_record->num_mech; m++)
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

				mech = SPF_mech_next( mech );
			}

			if ( !found_all )
				local_policy = NULL;
		}

	}


	/*
	 * evaluate the mechanisms
	 */

#define SPF_ADD_DNS_MECH() do { spf_response->num_dns_mech++; } while(0)

#define SPF_MAYBE_SKIP_CIDR() \
	do { \
		if ( data < data_end && data->dc.parm_type == PARM_CIDR ) \
			data = SPF_data_next( data ); \
	} while(0)

#define SPF_GET_LOOKUP_DATA() \
	do {												\
		if ( data == data_end )							\
			lookup = spf_request->cur_dom;				\
		else {											\
			err = SPF_record_expand_data( spf_server,	\
							spf_request, spf_response,	\
							data, ((char *)data_end - (char *)data),	\
							&buf, &buf_len );			\
			if (err == SPF_E_NO_MEMORY) {				\
				SPF_FREE_LOOKUP_DATA();					\
				return DONE_TEMPERR(err);				\
			}											\
			if (err) {									\
				SPF_FREE_LOOKUP_DATA();					\
				return DONE_PERMERR(err);				\
			}											\
			lookup = buf;								\
		}												\
	} while(0)
#define SPF_FREE_LOOKUP_DATA() \
	do { if (buf != NULL) { free(buf); buf = NULL; } } while(0)


	resolver = spf_server->resolver;

	mech = spf_record->mech_first;
	for (m = 0; m < spf_record->num_mech; m++) {

		/* This is as good a place as any. */
		/* XXX Rip this out and put it into a macro which can go into inner loops. */
		if (spf_response->num_dns_mech > spf_server->max_dns_mech) {
			SPF_FREE_LOOKUP_DATA();
			return DONE(SPF_RESULT_PERMERROR, SPF_REASON_NONE, SPF_E_BIG_DNS);
		}

		data = SPF_mech_data(mech);
		data_end = SPF_mech_end_data(mech);

		switch (mech->mech_type) {
		case MECH_A:
			SPF_ADD_DNS_MECH();
			SPF_MAYBE_SKIP_CIDR();
			SPF_GET_LOOKUP_DATA();

			if (spf_request->client_ver == AF_INET)
				fetch_ns_type = ns_t_a;
			else
				fetch_ns_type = ns_t_aaaa;

			rr_a = SPF_dns_lookup(resolver, lookup, fetch_ns_type, TRUE);

			if (spf_server->debug)
				SPF_debugf("found %d A records for %s  (herrno: %d)",
						rr_a->num_rr, lookup, rr_a->herrno);

			if (rr_a->herrno == TRY_AGAIN) {
				SPF_dns_rr_free(rr_a);
				SPF_FREE_LOOKUP_DATA();
				return DONE_TEMPERR(SPF_E_DNS_ERROR); /* REASON_MECH */
			}

			for (i = 0; i < rr_a->num_rr; i++) {
				/* XXX Should this be hoisted? */
				if (rr_a->rr_type != fetch_ns_type)
					continue;

				if (spf_request->client_ver == AF_INET) {
					if (SPF_i_match_ip4(spf_server, spf_request, mech, rr_a->rr[i]->a)) {
						SPF_dns_rr_free(rr_a);
						SPF_FREE_LOOKUP_DATA();
						return DONE_MECH(mech->prefix_type);
					}
				}
				else {
					if (SPF_i_match_ip6(spf_server, spf_request, mech, rr_a->rr[i]->aaaa)) {
						SPF_dns_rr_free(rr_a);
						SPF_FREE_LOOKUP_DATA();
						return DONE_MECH(mech->prefix_type);
					}
				}
			}

			SPF_dns_rr_free(rr_a);
			break;

		case MECH_MX:
			SPF_ADD_DNS_MECH();
			SPF_MAYBE_SKIP_CIDR();
			SPF_GET_LOOKUP_DATA();

			rr_mx = SPF_dns_lookup(resolver, lookup, ns_t_mx, TRUE);

			if (spf_server->debug)
				SPF_debugf("found %d MX records for %s  (herrno: %d)",
						rr_mx->num_rr, lookup, rr_mx->herrno);

			if (rr_mx->herrno == TRY_AGAIN) {
				SPF_dns_rr_free(rr_mx);
				SPF_FREE_LOOKUP_DATA();
				return DONE_TEMPERR(SPF_E_DNS_ERROR);
			}

			/* The maximum number of MX records we will inspect. */
			max_mx = rr_mx->num_rr;
			max_exceeded = 0;
			if (max_mx > spf_server->max_dns_mx) {
				max_exceeded = 1;
				max_mx = SPF_server_get_max_dns_mx(spf_server);
			}

			for (j = 0; j < max_mx; j++) {
				/* XXX Should this be hoisted? */
				if (rr_mx->rr_type != ns_t_mx)
					continue;

				if (spf_request->client_ver == AF_INET)
					fetch_ns_type = ns_t_a;
				else
					fetch_ns_type = ns_t_aaaa;

				rr_a = SPF_dns_lookup(resolver, rr_mx->rr[j]->mx,
									   fetch_ns_type, TRUE );

				if (spf_server->debug)
					SPF_debugf("%d: found %d A records for %s  (herrno: %d)",
							j, rr_a->num_rr, rr_mx->rr[j]->mx, rr_a->herrno);
				if (rr_a->herrno == TRY_AGAIN) {
					SPF_dns_rr_free(rr_mx);
					SPF_dns_rr_free(rr_a);
					SPF_FREE_LOOKUP_DATA();
					return DONE_TEMPERR(SPF_E_DNS_ERROR);
				}

				for (i = 0; i < rr_a->num_rr; i++) {
					/* XXX Should this be hoisted? */
					if (rr_a->rr_type != fetch_ns_type)
						continue;

					if (spf_request->client_ver == AF_INET) {
						if (SPF_i_match_ip4(spf_server, spf_request, mech,
										rr_a->rr[i]->a)) {
							SPF_dns_rr_free(rr_mx);
							SPF_dns_rr_free(rr_a);
							SPF_FREE_LOOKUP_DATA();
							return DONE(mech->prefix_type, SPF_REASON_MECH,
										 SPF_E_SUCCESS);
						}
					}
					else {
						if (SPF_i_match_ip6(spf_server, spf_request, mech,
										rr_a->rr[i]->aaaa)) {
							SPF_dns_rr_free(rr_mx);
							SPF_dns_rr_free(rr_a);
							SPF_FREE_LOOKUP_DATA();
							return DONE(mech->prefix_type, SPF_REASON_MECH,
										 SPF_E_SUCCESS);
						}
					}
				}
				SPF_dns_rr_free(rr_a);
			}

			SPF_dns_rr_free( rr_mx );
			if (max_exceeded) {
				SPF_FREE_LOOKUP_DATA();
				return DONE(SPF_RESULT_PERMERROR, SPF_REASON_NONE, SPF_E_BIG_DNS);
			}
			break;

		case MECH_PTR:
			SPF_ADD_DNS_MECH();
			SPF_GET_LOOKUP_DATA();

			if (spf_request->client_ver == AF_INET) {
				rr_ptr = SPF_dns_rlookup(resolver,
								spf_request->ipv4, ns_t_ptr, TRUE);

				if (spf_server->debug) {
					INET_NTOP(AF_INET, &spf_request->ipv4.s_addr,
										ip4_buf, sizeof(ip4_buf));
					SPF_debugf("got %d PTR records for %s (herrno: %d)",
							rr_ptr->num_rr, ip4_buf, rr_ptr->herrno);
				}

				if (rr_ptr->herrno == TRY_AGAIN) {
					SPF_dns_rr_free(rr_ptr);
					SPF_FREE_LOOKUP_DATA();
					return DONE_TEMPERR(SPF_E_DNS_ERROR);
				}


				/* The maximum number of PTR records we will inspect. */
				max_ptr = rr_ptr->num_rr;
				max_exceeded = 0;
				if (max_ptr > spf_server->max_dns_ptr) {
					max_exceeded = 1;
					max_ptr = SPF_server_get_max_dns_ptr(spf_server);
				}

				for (i = 0; i < max_ptr; i++) {
					/* XXX MX has a 'continue' case here which should be hoisted. */

					rr_a = SPF_dns_lookup(resolver,
							rr_ptr->rr[i]->ptr, ns_t_a, TRUE);

					if (spf_server->debug)
						SPF_debugf( "%d:  found %d A records for %s  (herrno: %d)",
								i, rr_a->num_rr, rr_ptr->rr[i]->ptr, rr_a->herrno );
					if (rr_a->herrno == TRY_AGAIN) {
						SPF_dns_rr_free(rr_ptr);
						SPF_dns_rr_free(rr_a);
						SPF_FREE_LOOKUP_DATA();
						return DONE_TEMPERR( SPF_E_DNS_ERROR );
					}

					for (j = 0; j < rr_a->num_rr; j++) {
						/* XXX MX has a 'continue' case here which should be hoisted. */

						if (spf_server->debug) {
							INET_NTOP(AF_INET, &rr_a->rr[j]->a.s_addr,
											ip4_buf, sizeof(ip4_buf));
							SPF_debugf("%d: %d:  found %s",
									i, j, ip4_buf);
						}

						if (rr_a->rr[j]->a.s_addr ==
										spf_request->ipv4.s_addr) {
							if (SPF_i_match_domain(spf_server,
											rr_ptr->rr[i]->ptr, lookup)) {
								SPF_dns_rr_free(rr_ptr);
								SPF_dns_rr_free(rr_a);
								SPF_FREE_LOOKUP_DATA();
								return DONE_MECH(mech->prefix_type);
							}
						}
					}
					SPF_dns_rr_free(rr_a);
				}
				SPF_dns_rr_free(rr_ptr);

				if (max_exceeded) {
					SPF_FREE_LOOKUP_DATA();
					return DONE(SPF_RESULT_PERMERROR, SPF_REASON_NONE, SPF_E_BIG_DNS);
				}
			}

			else if ( spf_request->client_ver == AF_INET6 ) {
				rr_ptr = SPF_dns_rlookup6(resolver,
								spf_request->ipv6, ns_t_ptr, TRUE);

				if ( spf_server->debug ) {
					INET_NTOP( AF_INET6, &spf_request->ipv6.s6_addr,
									   ip6_buf, sizeof( ip6_buf ) );
					SPF_debugf( "found %d PTR records for %s  (herrno: %d)",
							rr_ptr->num_rr, ip6_buf, rr_ptr->herrno );
				}
				if( rr_ptr->herrno == TRY_AGAIN ) {
					SPF_dns_rr_free(rr_ptr);
					SPF_FREE_LOOKUP_DATA();
					return DONE_TEMPERR( SPF_E_DNS_ERROR );
				}


				max_ptr = rr_ptr->num_rr;
				max_exceeded = 0;
				if (max_ptr > spf_server->max_dns_ptr) {
					max_ptr = SPF_server_get_max_dns_ptr(spf_server);
					max_exceeded = 1;
				}

				for (i = 0; i < max_ptr; i++) {
					/* XXX MX has a 'continue' case here which should be hoisted. */

					rr_aaaa = SPF_dns_lookup(resolver,
							rr_ptr->rr[i]->ptr, ns_t_aaaa, TRUE);

					if ( spf_server->debug )
						SPF_debugf("%d:  found %d AAAA records for %s  (herrno: %d)",
								i, rr_aaaa->num_rr, rr_ptr->rr[i]->ptr, rr_aaaa->herrno);
					if( rr_aaaa->herrno == TRY_AGAIN ) {
						SPF_dns_rr_free(rr_ptr);
						SPF_dns_rr_free(rr_aaaa);
						SPF_FREE_LOOKUP_DATA();
						return DONE_TEMPERR( SPF_E_DNS_ERROR );
					}

					for( j = 0; j < rr_aaaa->num_rr; j++ ) {
						/* XXX MX has a 'continue' case here which should be hoisted. */
						if ( spf_server->debug ) {
							INET_NTOP(AF_INET6, &rr_aaaa->rr[j]->aaaa.s6_addr,
											ip6_buf, sizeof(ip6_buf));
							SPF_debugf( "%d: %d:  found %s",
									i, j, ip6_buf );
						}

						if (memcmp(&rr_aaaa->rr[j]->aaaa,
								&spf_request->ipv6,
								sizeof(spf_request->ipv6)) == 0) {
							if (SPF_i_match_domain(spf_server,
											rr_ptr->rr[i]->ptr, lookup)) {
								SPF_dns_rr_free( rr_ptr );
								SPF_dns_rr_free(rr_aaaa);
								SPF_FREE_LOOKUP_DATA();
								return DONE_MECH( mech->prefix_type );
							}
						}
					}
					SPF_dns_rr_free(rr_aaaa);
				}
				SPF_dns_rr_free(rr_ptr);

				if (max_exceeded) {
					SPF_FREE_LOOKUP_DATA();
					return DONE(SPF_RESULT_PERMERROR, SPF_REASON_NONE, SPF_E_BIG_DNS);
				}
			}


			break;

		case MECH_INCLUDE:
		case MECH_REDIRECT:
			SPF_ADD_DNS_MECH();

			err = SPF_record_expand_data(spf_server,
					spf_request, spf_response,
					SPF_mech_data(mech), SPF_mech_data_len(mech),
					&buf, &buf_len );
			if ( err == SPF_E_NO_MEMORY ) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_TEMPERR( err );
			}
			if ( err ) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_PERMERR( err );
			}
			lookup = buf;

			/* XXX Maintain a stack depth here. Limit at 10. */
			if (strcmp(lookup, spf_request->cur_dom) == 0) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_PERMERR( SPF_E_RECURSIVE );
			}

			/*
			 * get the (compiled) SPF record
			 */

			spf_record_subr = NULL;
			/* Remember to reset this. */
			save_cur_dom = spf_request->cur_dom;
			spf_request->cur_dom = lookup;
			err = SPF_server_get_record(spf_server, spf_request,
							spf_response, &spf_record_subr);

			if ( spf_server->debug > 0 )
				SPF_debugf( "include/redirect:  got SPF record:  %s",
						SPF_strerror( err ) );

			if (err != SPF_E_SUCCESS) {
				spf_request->cur_dom = save_cur_dom;
				if (spf_record_subr)
					SPF_record_free(spf_record_subr);
				SPF_FREE_LOOKUP_DATA();
				if (err == SPF_E_DNS_ERROR)
					return DONE_TEMPERR( err );
				else
					return DONE_PERMERR( err );
			}

			SPF_ASSERT_NOTNULL(spf_record_subr);

			/*
			 * If we are a redirect which is not within the scope
			 * of any include.
			 */
			if (mech->mech_type == MECH_REDIRECT) {
				save_spf_response = NULL;
				if (spf_response->spf_record_exp == spf_record)
					spf_response->spf_record_exp = spf_record_subr;
				SPF_ASSERT_NOTNULL(spf_response->spf_record_exp);
			}
			else {
				save_spf_response = spf_response;
				spf_response = SPF_response_new(spf_request);
				if (! spf_response) {
					if (spf_record_subr)
						SPF_record_free(spf_record_subr);
					SPF_FREE_LOOKUP_DATA();
					return DONE_TEMPERR(SPF_E_NO_MEMORY);
				}
				spf_response->spf_record_exp = spf_record;
				SPF_ASSERT_NOTNULL(spf_response->spf_record_exp);
			}
			/*
			 * find out whether this configuration passes
			 */
			err = SPF_record_interpret(spf_record_subr,
							spf_request, spf_response, depth + 1);
			spf_request->cur_dom = save_cur_dom;
			/* Now, if we were a redirect, the child called done()
			 * and used spf_record_exp. In that case, we need not
			 * worry that spf_record_subr is invalid after the free.
			 * If we were not a redirect, then spf_record_subr
			 * is still the record it was in the first place.
			 * Thus we do not need to reset it now. */
			SPF_record_free(spf_record_subr);
			spf_record_subr = NULL;

			if ( spf_server->debug > 0 )
				SPF_debugf( "include/redirect:  executed SPF record:  %s  result: %s  reason: %s",
						SPF_strerror( err ),
						SPF_strresult( spf_response->result ),
						SPF_strreason( spf_response->reason ) );
			if (mech->mech_type == MECH_REDIRECT) {
				SPF_FREE_LOOKUP_DATA();
				return err;	/* One way or the other */
			}
			else { // if (spf_response->result != SPF_RESULT_INVALID) {
				/* Set everything up properly again. */
				spf_response_subr = spf_response;
				spf_response = save_spf_response;
				save_spf_response = NULL;

				/* Rewrite according to prefix of include */
				switch (SPF_response_result(spf_response_subr)) {
					case SPF_RESULT_PASS:
						/* Pass */
						SPF_FREE_LOOKUP_DATA();
						SPF_response_free(spf_response_subr);
						return DONE_MECH( mech->prefix_type );

					case SPF_RESULT_FAIL:
					case SPF_RESULT_SOFTFAIL:
					case SPF_RESULT_NEUTRAL:
						/* No match */
						SPF_response_free(spf_response_subr);
						break;

					case SPF_RESULT_TEMPERROR:
						/* Generate TempError */
						err = SPF_response_errcode(spf_response_subr);
						SPF_FREE_LOOKUP_DATA();
						SPF_response_free(spf_response_subr);
						return DONE_TEMPERR( err );

					case SPF_RESULT_NONE:
						/* Generate PermError */
						SPF_FREE_LOOKUP_DATA();
						SPF_response_free(spf_response_subr);
						return DONE_PERMERR(SPF_E_INCLUDE_RETURNED_NONE);
					case SPF_RESULT_PERMERROR:
					case SPF_RESULT_INVALID:
						/* Generate PermError */
						err = SPF_response_errcode(spf_response_subr);
						SPF_FREE_LOOKUP_DATA();
						SPF_response_free(spf_response_subr);
						return DONE_PERMERR( err );

				}
#if 0
				SPF_FREE_LOOKUP_DATA();
				return err;	/* The sub-interpret called done() */
#endif
			}

			break;

		case MECH_IP4:
			memcpy(&addr4, SPF_mech_ip4_data(mech), sizeof(addr4));
			if ( SPF_i_match_ip4( spf_server, spf_request, mech, addr4 ) ) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_MECH( mech->prefix_type );
			}
			break;

		case MECH_IP6:
			memcpy(&addr6, SPF_mech_ip6_data(mech), sizeof(addr6));
			if ( SPF_i_match_ip6( spf_server, spf_request, mech, addr6 ) ) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_MECH( mech->prefix_type );
			}
			break;

		case MECH_EXISTS:
			SPF_ADD_DNS_MECH();

			err = SPF_record_expand_data(spf_server,
							spf_request, spf_response,
							SPF_mech_data(mech),SPF_mech_data_len(mech),
							&buf, &buf_len);
			if (err != SPF_E_SUCCESS) {
				SPF_FREE_LOOKUP_DATA();
				return DONE_TEMPERR( err );
			}
			lookup = buf;

			rr_a = SPF_dns_lookup(resolver, lookup, ns_t_a, FALSE );

			if ( spf_server->debug )
				SPF_debugf( "found %d A records for %s  (herrno: %d)",
						rr_a->num_rr, lookup, rr_a->herrno );

			if( rr_a->herrno == TRY_AGAIN ) {
				SPF_dns_rr_free(rr_a);
				SPF_FREE_LOOKUP_DATA();
				return DONE_TEMPERR(SPF_E_DNS_ERROR);
			}
			if ( rr_a->num_rr > 0 ) {
				SPF_dns_rr_free(rr_a);
				SPF_FREE_LOOKUP_DATA();
				return DONE_MECH(mech->prefix_type);
			}

			SPF_dns_rr_free(rr_a);
			break;

		case MECH_ALL:
			SPF_FREE_LOOKUP_DATA();
			if (mech->prefix_type == PREFIX_UNKNOWN)
				return DONE_PERMERR(SPF_E_UNKNOWN_MECH);
			return DONE_MECH(mech->prefix_type);
			break;

		default:
			SPF_FREE_LOOKUP_DATA();
			return DONE_PERMERR(SPF_E_UNKNOWN_MECH);
			break;
		}

		/*
		 * execute the local policy
		 */

		if ( mech == local_policy ) {
			err = SPF_record_interpret(spf_server->local_policy,
							spf_request, spf_response, depth + 1);

			if ( spf_server->debug > 0 )
				SPF_debugf( "local_policy:  executed SPF record:  %s  result: %s  reason: %s",
							SPF_strerror( err ),
							SPF_strresult( spf_response->result ),
							SPF_strreason( spf_response->reason ) );

			if (spf_response->result != SPF_RESULT_INVALID) {
				SPF_FREE_LOOKUP_DATA();
				return err;
			}
		}

		mech = SPF_mech_next( mech );
	}

	SPF_FREE_LOOKUP_DATA();
	/* falling off the end is the same as ?all */
	return DONE( SPF_RESULT_NEUTRAL, SPF_REASON_DEFAULT, SPF_E_SUCCESS );
}
