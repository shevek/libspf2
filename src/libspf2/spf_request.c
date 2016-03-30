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
#include "spf_request.h"
#include "spf_internal.h"

#define SPF_FREE(x) \
		do { if (x) free(x); (x) = NULL; } while(0)

SPF_request_t *
SPF_request_new(SPF_server_t *spf_server)
{
	SPF_request_t	*sr;

	sr = (SPF_request_t *)malloc(sizeof(SPF_request_t));
	if (! sr)
		return sr;
	memset(sr, 0, sizeof(SPF_request_t));

	sr->spf_server = spf_server;
	sr->client_ver = AF_UNSPEC;
	sr->ipv4.s_addr = htonl(INADDR_ANY);
	sr->ipv6 = in6addr_any;

	return sr;
}

void
SPF_request_free(SPF_request_t *sr)
{
	SPF_ASSERT_NOTNULL(sr);
	SPF_FREE(sr->client_dom);
	SPF_FREE(sr->helo_dom);
	SPF_FREE(sr->env_from);
	SPF_FREE(sr->env_from_lp);
	SPF_FREE(sr->env_from_dp);
	free(sr);
}

SPF_errcode_t
SPF_request_set_ipv4(SPF_request_t *sr, struct in_addr addr)
{
	if (sr->client_dom) {
		free(sr->client_dom);
		sr->client_dom = NULL;
	}
	sr->client_ver = AF_INET;
	sr->ipv4 = addr;
	return SPF_E_SUCCESS;
}

SPF_errcode_t
SPF_request_set_ipv6(SPF_request_t *sr, struct in6_addr addr)
{
	if (sr->client_dom) {
		free(sr->client_dom);
		sr->client_dom = NULL;
	}
	sr->client_ver = AF_INET6;
	sr->ipv6 = addr;
	return SPF_E_SUCCESS;
}

SPF_errcode_t
SPF_request_set_ipv4_str(SPF_request_t *sr, const char *astr)
{
	struct in_addr	addr;
	if (astr == NULL)
		astr = "0.0.0.0";
	if (inet_pton(AF_INET, astr, &addr) <= 0)
		return SPF_E_INVALID_IP4;
	return SPF_request_set_ipv4(sr, addr);
}

SPF_errcode_t
SPF_request_set_ipv6_str(SPF_request_t *sr, const char *astr)
{
	struct in6_addr	addr;
	if (astr == NULL)
		astr = "::";
	if (inet_pton(AF_INET6, astr, &addr) <= 0)
		return SPF_E_INVALID_IP6;
	return SPF_request_set_ipv6(sr, addr);
}

SPF_errcode_t
SPF_request_set_helo_dom(SPF_request_t *sr, const char *dom)
{
	SPF_ASSERT_NOTNULL(dom);
	SPF_FREE(sr->helo_dom);
	sr->helo_dom = strdup(dom);
	if (! sr->helo_dom)
		return SPF_E_NO_MEMORY;
	/* set cur_dom and env_from? */
	if (sr->env_from == NULL)
		return SPF_request_set_env_from(sr, dom);
	return SPF_E_SUCCESS;
}

const char *
SPF_request_get_rec_dom(SPF_request_t *sr)
{
	SPF_server_t	*spf_server;
	spf_server = sr->spf_server;
	return spf_server->rec_dom;
}

int
SPF_request_set_env_from(SPF_request_t *sr, const char *from)
{
	char	*cp;
	size_t	 len;

	SPF_ASSERT_NOTNULL(from);
	SPF_FREE(sr->env_from);
	SPF_FREE(sr->env_from_lp);
	SPF_FREE(sr->env_from_dp);

	if (*from == '\0' && sr->helo_dom != NULL)
		from = sr->helo_dom;
	cp = strrchr(from, '@');
	if (cp && (cp != from)) {
		sr->env_from = strdup(from);
		if (! sr->env_from)
			return SPF_E_NO_MEMORY;

		len = cp - from;
		sr->env_from_lp = malloc(len + 1);
		if (!sr->env_from_lp) {
			SPF_FREE(sr->env_from);
			return SPF_E_NO_MEMORY;
		}
		strncpy(sr->env_from_lp, from, len);
		sr->env_from_lp[len] = '\0';
		sr->env_from_dp = strdup(cp + 1);
		if (!sr->env_from_dp) {
			SPF_FREE(sr->env_from);
			SPF_FREE(sr->env_from_lp);
			return SPF_E_NO_MEMORY;
		}
	}
	else {
		if (cp == from) from++; /* "@domain.example" */
		len = sizeof("postmaster@") + strlen(from);
		sr->env_from = malloc(len + 1);	/* sizeof("") == 1? */
		if (! sr->env_from)
			return SPF_E_NO_MEMORY;
		sprintf(sr->env_from, "postmaster@%s", from);
		sr->env_from_lp = strdup("postmaster");
		if (!sr->env_from_lp) {
			SPF_FREE(sr->env_from);
			return SPF_E_NO_MEMORY;
		}
		sr->env_from_dp = strdup(from);
		if (!sr->env_from_dp) {
			SPF_FREE(sr->env_from);
			SPF_FREE(sr->env_from_lp);
			return SPF_E_NO_MEMORY;
		}
	}

	return 0;	// SPF_E_SUCCESS
}

const char *
SPF_request_get_client_dom(SPF_request_t *sr)
{
	SPF_server_t	*spf_server;

	SPF_ASSERT_NOTNULL(sr);
	spf_server = sr->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	if (sr->client_dom == NULL) {
		sr->client_dom = SPF_dns_get_client_dom(spf_server->resolver,
						sr);
	}
	return sr->client_dom;
}

int
SPF_request_is_loopback(SPF_request_t *sr)
{
    if (sr->client_ver == AF_INET) {
		if ((ntohl(sr->ipv4.s_addr) & IN_CLASSA_NET) ==
						(IN_LOOPBACKNET << 24)) {
			return TRUE;
		}
    }
    else if (sr->client_ver == AF_INET6) {
		if (IN6_IS_ADDR_LOOPBACK(&sr->ipv6))
			return TRUE;
    }
    return FALSE;
}

static SPF_errcode_t
SPF_request_prepare(SPF_request_t *sr)
{
	if (sr->use_helo)
		sr->cur_dom = sr->helo_dom;
	else
		sr->cur_dom = sr->env_from_dp;
	return SPF_E_SUCCESS;
}
 
/**
 * The common tail-end of a few methods below.
 */
static SPF_errcode_t
SPF_request_query_record(SPF_request_t *spf_request,
				SPF_response_t *spf_response,
				SPF_record_t *spf_record,
				SPF_errcode_t err)
{
	if (err != SPF_E_SUCCESS) {
		if (spf_record)
			SPF_record_free(spf_record);
		SPF_i_done(spf_response, spf_response->result, spf_response->reason, spf_response->err);
		return err;
	}
	/* Now, in theory, SPF_response_errors(spf_response) == 0 */
	if (SPF_response_errors(spf_response) > 0)
		SPF_infof("Warning: %d errors in response, "
						"but no error code. Evaluating.",
						SPF_response_errors(spf_response));
	/* If we get here, spf_record better not be NULL */
	spf_response->spf_record_exp = spf_record;
	err = SPF_record_interpret(spf_record,
					spf_request, spf_response, 0);
	SPF_record_free(spf_record);
	spf_response->spf_record_exp = NULL;

	return err;
}

/**
 * The big entry point.
 */
SPF_errcode_t
SPF_request_query_mailfrom(SPF_request_t *spf_request,
				SPF_response_t **spf_responsep)
{
	SPF_server_t	*spf_server;
	SPF_record_t	*spf_record;
	SPF_errcode_t	 err;

	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	*spf_responsep = SPF_response_new(spf_request);
	if (! *spf_responsep)
		return SPF_E_NO_MEMORY;

	/* Give localhost a free ride */
	if (SPF_request_is_loopback(spf_request))
		return SPF_i_done(*spf_responsep, SPF_RESULT_PASS,
						SPF_REASON_LOCALHOST, SPF_E_SUCCESS);

	SPF_request_prepare(spf_request);

	err = SPF_server_get_record(spf_server, spf_request,
					*spf_responsep, &spf_record);
	return SPF_request_query_record(spf_request, *spf_responsep,
					spf_record, err);
}

/* This interface isn't finalised. */
SPF_errcode_t
SPF_request_query_fallback(SPF_request_t *spf_request,
				SPF_response_t **spf_responsep,
				const char *record)
{
	SPF_server_t	*spf_server;
	SPF_record_t	*spf_record;
	SPF_errcode_t	 err;

	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	*spf_responsep = SPF_response_new(spf_request);
	if (! *spf_responsep)
		return SPF_E_NO_MEMORY;

	/* Give localhost a free ride */
	if (SPF_request_is_loopback(spf_request))
		return SPF_i_done(*spf_responsep, SPF_RESULT_PASS,
						SPF_REASON_LOCALHOST, SPF_E_SUCCESS);

	SPF_request_prepare(spf_request);

	err = SPF_record_compile(spf_server,
					*spf_responsep, &spf_record,
					record);
	return SPF_request_query_record(spf_request, *spf_responsep,
					spf_record, err);
}

/**
 * This replaces _2mx
 *
 * build record as SPF_VER_STR " mx:%s"
 * Set cur_dom to the rcpt_to domain.
 * Query on the 'fixed' 2mx record.
 * Clobber the primary result.
 */
/* FIXME: Check the implementation of this. */
SPF_errcode_t
SPF_request_query_rcptto(SPF_request_t *spf_request,
				SPF_response_t **spf_responsep,
				const char *rcpt_to)
{
	SPF_server_t	*spf_server;
	SPF_record_t	*spf_record;
	SPF_errcode_t	 err;
	const char		*rcpt_to_dom;
	char			*record;
	size_t			 len;

	SPF_ASSERT_NOTNULL(spf_request);
	spf_server = spf_request->spf_server;
	SPF_ASSERT_NOTNULL(spf_server);

	*spf_responsep = SPF_response_new(spf_request);
	if (! *spf_responsep)
		return SPF_E_NO_MEMORY;

	/* Give localhost a free ride */
	if (SPF_request_is_loopback(spf_request))
		return SPF_i_done(*spf_responsep, SPF_RESULT_PASS,
						SPF_REASON_LOCALHOST, SPF_E_SUCCESS);

	rcpt_to_dom = strchr(rcpt_to, '@');
	if (rcpt_to_dom == NULL)
		rcpt_to_dom = rcpt_to;
	else
		rcpt_to_dom++;
	spf_request->cur_dom = rcpt_to_dom;

	len = sizeof(SPF_VER_STR) + 64 + strlen(rcpt_to_dom);
	record = malloc(len);
	if (! record)
		return SPF_E_NO_MEMORY;
	snprintf(record, len, SPF_VER_STR " mx:%s", rcpt_to_dom);
	err = SPF_record_compile(spf_server,
					*spf_responsep, &spf_record,
					record);
	free(record);
	return SPF_request_query_record(spf_request, *spf_responsep,
					spf_record, err);
}
