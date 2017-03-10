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

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif


#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_rr.h"

/**
 * @file
 * Audited, 2008-09-13, Shevek.
 */

SPF_dns_rr_t *
SPF_dns_rr_new_nxdomain(SPF_dns_server_t *spf_dns_server,
				const char *domain)
{
	return SPF_dns_rr_new_init(spf_dns_server,
					domain, ns_t_any, 0, HOST_NOT_FOUND);
}

SPF_dns_rr_t *
SPF_dns_rr_new_init(SPF_dns_server_t *spf_dns_server,
				const char *domain,
				ns_type rr_type, int ttl,
				SPF_dns_stat_t herrno)
{
    SPF_dns_rr_t	*spfrr;

    spfrr = SPF_dns_rr_new();
    if (spfrr == NULL)
		return spfrr;

    spfrr->source = spf_dns_server;
	if (domain && (domain[0] != '\0')) {
		spfrr->domain = strdup(domain);
		if (spfrr->domain == NULL) {
			SPF_dns_rr_free(spfrr);
			return NULL;
		}
		spfrr->domain_buf_len = strlen(domain) + 1;
	}
	else {
		spfrr->domain = NULL;
		spfrr->domain_buf_len = 0;
	}
    spfrr->rr_type = rr_type;
    spfrr->ttl = ttl;
    spfrr->herrno = herrno;

    return spfrr;
}

SPF_dns_rr_t *
SPF_dns_rr_new()
{
    SPF_dns_rr_t	*spfrr;

    spfrr = malloc(sizeof(SPF_dns_rr_t));
    if (spfrr == NULL)
		return spfrr;
	memset(spfrr, 0, sizeof(SPF_dns_rr_t));

	spfrr->domain = NULL;
	spfrr->domain_buf_len = 0;
	spfrr->rr_type = ns_t_invalid;
	spfrr->num_rr = 0;
	spfrr->ttl = 0;
	spfrr->utc_ttl = 0;
	spfrr->herrno = HOST_NOT_FOUND;

    return spfrr;
}

void
SPF_dns_rr_free(SPF_dns_rr_t *spfrr)
{
	int	 i;

	if (spfrr->domain)
		free(spfrr->domain);
	if (spfrr->rr) {
		for (i = 0; i < spfrr->rr_buf_num; i++)
			if (spfrr->rr[i])
				free(spfrr->rr[i]);
		free(spfrr->rr);
	}
	if (spfrr->rr_buf_len)
		free(spfrr->rr_buf_len);
	if(spfrr->hook)
		free(spfrr->hook);
	free(spfrr);
}

SPF_errcode_t
SPF_dns_rr_buf_realloc(SPF_dns_rr_t *spfrr, int idx, size_t len)
{
	SPF_dns_rr_data_t	**new_data;
	size_t				 *new_buf_len;
	int					  new_num;
	void				 *new_rr;
	int					  j;
	
	if (spfrr->rr_buf_num <= idx) {
		/* allocate lots so we don't have to remalloc often */
		new_num = spfrr->rr_buf_num + (idx + (idx >> 2) + 4 );

		new_data = realloc(spfrr->rr,
						new_num * sizeof(*new_data));
		if (new_data == NULL)
			return SPF_E_NO_MEMORY;
		spfrr->rr = new_data;
		
		new_buf_len = realloc(spfrr->rr_buf_len,
					   new_num * sizeof(*new_buf_len));
		if (new_buf_len == NULL)
			return SPF_E_NO_MEMORY;
		spfrr->rr_buf_len = new_buf_len;
		
		for(j = spfrr->rr_buf_num; j < new_num; j++) {
			spfrr->rr[j] = NULL;
			spfrr->rr_buf_len[j] = 0;
		}

		spfrr->rr_buf_num = new_num;
	}

    if (len < sizeof(SPF_dns_rr_data_t))
		len = sizeof(SPF_dns_rr_data_t);
    if (spfrr->rr_buf_len[idx] >= len)
		return SPF_E_SUCCESS;

	new_rr = realloc(spfrr->rr[idx], len);
    if (new_rr == NULL)
		return SPF_E_NO_MEMORY;
    spfrr->rr[idx] = new_rr;
    spfrr->rr_buf_len[idx] = len;

    return SPF_E_SUCCESS;
}


/**
 * This function may return both an error code and an rr, or
 * one, or neither. 
 *
 * This function generates a valgrind error because strlen always reads in
 * blocks of 4 bytes, and can overrun the end of the allocated buffers.
 */
SPF_errcode_t
SPF_dns_rr_dup(SPF_dns_rr_t **dstp, SPF_dns_rr_t *src)
{
	SPF_dns_rr_t	*dst;
    SPF_errcode_t	err;
    int			i;

 	SPF_ASSERT_NOTNULL(src);
 	SPF_ASSERT_NOTNULL(dstp);
	dst = SPF_dns_rr_new_init(src->source,
					src->domain, src->rr_type, src->ttl, src->herrno);
	if (!dst) {
		*dstp = NULL;
		return SPF_E_NO_MEMORY;
	}
	*dstp = dst;

    dst->utc_ttl = src->utc_ttl;
    dst->num_rr  = src->num_rr;

#define SPF_DNS_RR_REALLOC(d, i, s) do { \
			err = SPF_dns_rr_buf_realloc(d, i, s); \
			if (err) return err; \
		} while(0)

    for (i = dst->num_rr - 1; i >= 0; i--) {
		switch (dst->rr_type) {
			case ns_t_a:
				SPF_DNS_RR_REALLOC(dst, i, sizeof(SPF_dns_rr_data_t));
				dst->rr[i]->a = src->rr[i]->a;
				break;
				
			case ns_t_ptr:
				SPF_DNS_RR_REALLOC(dst, i, strlen(src->rr[i]->ptr) + 1);
				strcpy(dst->rr[i]->ptr, src->rr[i]->ptr);
				break;
				
			case ns_t_mx:
				SPF_DNS_RR_REALLOC(dst, i, strlen(src->rr[i]->mx) + 1);
				strcpy(dst->rr[i]->mx, src->rr[i]->mx);
				break;
				
			case ns_t_txt:
				SPF_DNS_RR_REALLOC(dst, i, strlen(src->rr[i]->txt) + 1);
				strcpy(dst->rr[i]->txt, src->rr[i]->txt);
				break;
				
			case ns_t_aaaa:
				SPF_DNS_RR_REALLOC(dst, i, sizeof(SPF_dns_rr_data_t));
				dst->rr[i]->aaaa = src->rr[i]->aaaa;
				break;
				
			default:
				SPF_warningf("Attempt to dup unknown rr type %d",
								dst->rr_type);
				break;
		}
	}

    return SPF_E_SUCCESS;
}
