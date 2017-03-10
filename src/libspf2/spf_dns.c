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


/*
 * helper functions
 */

static void
SPF_dns_debug_pre(SPF_dns_server_t *spf_dns_server, const char *domain,
				ns_type rr_type, int should_cache)
{
	if (spf_dns_server->debug) {
		SPF_debugf("DNS[%s] lookup: %s %s (%d)",
			spf_dns_server->name, domain,
			SPF_strrrtype(rr_type), rr_type);
	}
}

static void
SPF_dns_debug_post(SPF_dns_server_t *spf_dns_server, SPF_dns_rr_t *spfrr)
{
	if (spf_dns_server->debug) {
		char	ip4_buf[ INET_ADDRSTRLEN ];
		char	ip6_buf[ INET6_ADDRSTRLEN ];
		int		i;

		SPF_debugf("DNS[%s] found record", spf_dns_server->name);
		SPF_debugf("    DOMAIN: %s  TYPE: %s (%d)",
			spfrr->domain,
			SPF_strrrtype(spfrr->rr_type), spfrr->rr_type);
		SPF_debugf("    TTL: %ld  RR found: %d  herrno: %d  source: %s",
			(long)spfrr->ttl, spfrr->num_rr, spfrr->herrno,
			(spfrr->source
				? (spfrr->source->name
					? spfrr->source->name
					: "(unnamed source)")
				: "(null source)"));
		for (i = 0; i < spfrr->num_rr; i++) {
			switch (spfrr->rr_type) {
				case ns_t_a:
					SPF_debugf("    - A: %s",
							inet_ntop(AF_INET, &(spfrr->rr[i]->a),
								ip4_buf, sizeof(ip4_buf)));
					break;

				case ns_t_ptr:
					SPF_debugf("    - PTR: %s", spfrr->rr[i]->ptr);
					break;

				case ns_t_mx:
					SPF_debugf("    - MX: %s", spfrr->rr[i]->mx);
					break;

				case ns_t_txt:
					SPF_debugf("    - TXT: %s", spfrr->rr[i]->txt);
					break;

				case ns_t_aaaa:
					SPF_debugf("    - AAAA: %s",
							inet_ntop(AF_INET6, &(spfrr->rr[i]->aaaa),
								ip6_buf, sizeof(ip6_buf)));
					break;

				default:
					SPF_debugf("    - Unknown RR type");
					break;
			}
		}
	}
}

void
SPF_dns_free(SPF_dns_server_t *spf_dns_server)
{
	SPF_dns_server_t	*layer_below;

	SPF_ASSERT_NOTNULL(spf_dns_server);
	// SPF_ASSERT_NOTNULL(spf_dns_server->destroy);
	layer_below = spf_dns_server->layer_below;

	/* If this is not set, we assume someone else knows, and will destroy it. */
	if (spf_dns_server->destroy) {
		spf_dns_server->destroy(spf_dns_server);
		if (layer_below != NULL)
			SPF_dns_free(layer_below);
	}
}

SPF_dns_rr_t *
SPF_dns_lookup(SPF_dns_server_t *spf_dns_server, const char *domain,
				ns_type rr_type, int should_cache)
{
	SPF_dns_rr_t	*spfrr;
	
	SPF_ASSERT_NOTNULL(spf_dns_server);
	SPF_dns_debug_pre(spf_dns_server, domain, rr_type, should_cache);
	SPF_ASSERT_NOTNULL(spf_dns_server->lookup);
	spfrr = spf_dns_server->lookup(spf_dns_server,
					domain, rr_type, should_cache);
	if (spfrr == NULL)
		SPF_error( "SPF DNS layer return NULL during a lookup." );
	SPF_dns_debug_post(spf_dns_server, spfrr);
	return spfrr;
}

SPF_dns_rr_t *
SPF_dns_rlookup(SPF_dns_server_t *spf_dns_server, struct in_addr ipv4,
				ns_type rr_type, int should_cache)
{
	char			 domain[ sizeof("111.222.333.444.in-addr.arpa") ];
	union {
		struct in_addr	ipv4;
		unsigned char	x[4];
	} tmp;

	/*
	 * make sure the scratch buffer is big enough
	 */
	tmp.ipv4 = ipv4;

	snprintf(domain, sizeof(domain), "%d.%d.%d.%d.in-addr.arpa",
		 tmp.x[3], tmp.x[2], tmp.x[1], tmp.x[0]);

	return SPF_dns_lookup(spf_dns_server, domain, rr_type,should_cache);
}

SPF_dns_rr_t *
SPF_dns_rlookup6(SPF_dns_server_t *spf_dns_server,
				struct in6_addr ipv6, ns_type rr_type, int should_cache)
{
	char	 domain[ sizeof(struct in6_addr) * 4 + sizeof(".ip6.arpa" ) + 1];  /* nibbles */
	char	*p, *p_end;
	int		 i;

	p = domain;
	p_end = p + sizeof( domain );
			
	for (i = sizeof(struct in6_addr) - 1; i >= 0; i--) {
		p += snprintf(p, p_end - p, "%.1x.%.1x.",
					ipv6.s6_addr[i] & 0xf,
					ipv6.s6_addr[i] >> 4);
	}

	/* squash the final '.' */
	p += snprintf(p, p_end - p, "ip6.arpa");

	return SPF_dns_lookup(spf_dns_server, domain, rr_type, should_cache);
}



/* XXX FIXME */
/*
 * Set the SMTP client domain name
 */

/**
 * This may return NULL if the strdup() fails.
 *
 * This ought to be refactored with the PTR code in the interpreter.
 */
char *
SPF_dns_get_client_dom( SPF_dns_server_t *spf_dns_server,
				SPF_request_t *sr )
{
	char	 *client_dom;
	SPF_dns_rr_t *rr_ptr;
	SPF_dns_rr_t *rr_a;
	SPF_dns_rr_t *rr_aaaa;
	
	int		i, j;
	
	int		max_ptr;

	SPF_ASSERT_NOTNULL(spf_dns_server);
	SPF_ASSERT_NOTNULL(sr);


/*
 * The "p" macro expands to the validated domain name of the SMTP
 * client.  The validation procedure is described in section 5.4.  If
 * there are no validated domain names, the word "unknown" is
 * substituted.  If multiple validated domain names exist, the first one
 * returned in the PTR result is chosen.
 *
 *
 *   sending-host_names := ptr_lookup(sending-host_IP);
 *   for each name in (sending-host_names) {
 *     IP_addresses := a_lookup(name);
 *     if the sending-host_IP is one of the IP_addresses {
 *       validated_sending-host_names += name;
 *   } }
 */

	if ( sr->client_ver == AF_INET ) {
		rr_ptr = SPF_dns_rlookup( spf_dns_server, sr->ipv4, ns_t_ptr, FALSE );
		
		max_ptr = rr_ptr->num_rr;
		/* XXX TODO? Or irrelevant?
		if (max_ptr > sr->max_dns_ptr)
			max_ptr = sr->max_dns_ptr;
		*/
		/* XXX do we want to report if this is exceeded and we
		 * might've missed a validated name because of that?
		 */
		if (max_ptr > SPF_MAX_DNS_PTR)
			max_ptr = SPF_MAX_DNS_PTR;

		for (i = 0; i < max_ptr; i++) {
			rr_a = SPF_dns_lookup(spf_dns_server, rr_ptr->rr[i]->ptr, ns_t_a, FALSE);

			for (j = 0; j < rr_a->num_rr; j++) {
				if (rr_a->rr[j]->a.s_addr == sr->ipv4.s_addr) {
					client_dom = strdup(rr_ptr->rr[i]->ptr);
					SPF_dns_rr_free(rr_ptr);
					SPF_dns_rr_free(rr_a);
					return client_dom;
				}
			}
			SPF_dns_rr_free(rr_a);
		}
		SPF_dns_rr_free(rr_ptr);
	}
		
	else if ( sr->client_ver == AF_INET6 ) {
		rr_ptr = SPF_dns_rlookup6( spf_dns_server, sr->ipv6, ns_t_ptr, FALSE );

		max_ptr = rr_ptr->num_rr;
		/*
		if ( max_ptr > sr->max_dns_ptr )
			max_ptr = sr->max_dns_ptr;
		*/
		/* XXX do we want to report if this is exceeded and we
		 * might've missed a validated name because of that?
		 */
		if ( max_ptr > SPF_MAX_DNS_PTR )
			max_ptr = SPF_MAX_DNS_PTR;

		for( i = 0; i < max_ptr; i++ ) {
			rr_aaaa = SPF_dns_lookup( spf_dns_server, rr_ptr->rr[i]->ptr, ns_t_aaaa, FALSE );

			for( j = 0; j < rr_aaaa->num_rr; j++ ) {
				if ( memcmp( &rr_aaaa->rr[j]->aaaa, &sr->ipv6,
						 sizeof( sr->ipv6 ) ) == 0 ) {
					client_dom = strdup( rr_ptr->rr[i]->ptr );
					SPF_dns_rr_free( rr_ptr );
					SPF_dns_rr_free( rr_aaaa );
					return client_dom;
				}
			}
			SPF_dns_rr_free( rr_aaaa );
		}
		SPF_dns_rr_free( rr_ptr );
	}

	return strdup( "unknown" );
}
