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



#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_null.h"


static SPF_dns_rr_t *
SPF_dns_null_lookup(SPF_dns_server_t *spf_dns_server,
				const char *domain, ns_type rr_type, int should_cache)
{
    if (spf_dns_server->layer_below)
		return SPF_dns_lookup(spf_dns_server->layer_below,
						domain, rr_type, should_cache);
	return SPF_dns_rr_new_nxdomain(spf_dns_server, domain);
}

static void
SPF_dns_null_free( SPF_dns_server_t *spf_dns_server )
{
	SPF_ASSERT_NOTNULL(spf_dns_server);
	free(spf_dns_server);
}

SPF_dns_server_t *
SPF_dns_null_new(SPF_dns_server_t *spf_dns_server_below,
				const char *name, int debug)
{
	SPF_dns_server_t		*spf_dns_server;

    spf_dns_server = malloc(sizeof(SPF_dns_server_t));
    if ( spf_dns_server == NULL )
		return NULL;
	memset(spf_dns_server, 0, sizeof(SPF_dns_server_t));

    if (name ==  NULL)
		name = "null";

    spf_dns_server->destroy      = SPF_dns_null_free;
    spf_dns_server->lookup       = SPF_dns_null_lookup;
    spf_dns_server->get_spf      = NULL;
    spf_dns_server->get_exp      = NULL;
    spf_dns_server->add_cache    = NULL;
    spf_dns_server->layer_below  = spf_dns_server_below;
	spf_dns_server->name         = name;
	spf_dns_server->debug        = debug;

    return spf_dns_server;
}
