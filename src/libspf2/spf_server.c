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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif 

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif 


#include "spf.h"
#include "spf_response.h"
#include "spf_record.h"
#include "spf_server.h"
#include "spf_dns.h"
#include "spf_dns_resolv.h"
#include "spf_dns_cache.h"
#include "spf_dns_zone.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"


__attribute__((warn_unused_result))
static SPF_errcode_t
SPF_server_set_rec_dom_ghbn(SPF_server_t *sp)
{
	sp->rec_dom = malloc(HOST_NAME_MAX);
	if (! sp->rec_dom)
		return SPF_E_NO_MEMORY;
#ifdef _WIN32
	gethostnameFQDN(sp->rec_dom, HOST_NAME_MAX);
	return 0;	/* XXX FIXME? */
#else
	if (gethostname(sp->rec_dom, HOST_NAME_MAX) < 0)
		/* XXX Error using strerror. */
		return SPF_E_INTERNAL_ERROR;
#endif
	return SPF_E_SUCCESS;
}

static void
SPF_server_new_common_pre(SPF_server_t *sp, int debug)
{
	SPF_errcode_t		 err;

	memset(sp, 0, sizeof(SPF_server_t));

	sp->max_dns_mech = SPF_MAX_DNS_MECH;
	sp->max_dns_ptr = SPF_MAX_DNS_PTR;
	sp->max_dns_mx = SPF_MAX_DNS_MX;
	sp->debug = debug;

	err = SPF_server_set_rec_dom_ghbn(sp);
	if (err != SPF_E_SUCCESS)
		SPF_error("Failed to set rec_dom using gethostname()");
}

static void
SPF_server_new_common_post(SPF_server_t *sp)
{
	SPF_response_t		*spf_response;
	SPF_errcode_t		 err;

	spf_response = NULL;
	err = SPF_server_set_explanation(sp, SPF_DEFAULT_EXP,
					&spf_response);
	if (err != SPF_E_SUCCESS)
		SPF_errorf("Error code %d compiling default explanation", err);
	if (spf_response) {
		/* XXX Print the errors?! */
		if (SPF_response_messages(spf_response) > 0)
			SPF_error("Response errors compiling default explanation");
		SPF_response_free(spf_response);
	}

	spf_response = NULL;
	err = SPF_server_set_localpolicy(sp, "", 0, &spf_response);
	if (err != SPF_E_SUCCESS)
		SPF_errorf("Error code %d compiling default whitelist", err);
	if (spf_response) {
		/* XXX Print the errors?! */
		if (SPF_response_messages(spf_response) > 0)
			SPF_error("Response errors compiling default whitelist");
		SPF_response_free(spf_response);
	}
}

SPF_server_t *
SPF_server_new(SPF_server_dnstype_t dnstype, int debug)
{
	SPF_dns_server_t	*dc_r;
	SPF_dns_server_t	*dc_c;
	SPF_dns_server_t	*dc_z;
	SPF_server_t		*sp;

	sp = (SPF_server_t *)malloc(sizeof(SPF_server_t));
	if (! sp)
		return sp;
	SPF_server_new_common_pre(sp, debug);
	sp->destroy_resolver = 1;

	switch (dnstype) {
		case SPF_DNS_RESOLV:
			dc_r = SPF_dns_resolv_new(NULL, NULL, debug);
			if (dc_r == NULL)
				SPF_error("Failed to create DNS resolver");
			sp->resolver = dc_r;
			break;

		case SPF_DNS_CACHE:
			dc_r = SPF_dns_resolv_new(NULL, NULL, debug);
			if (dc_r == NULL)
				SPF_error("Failed to create DNS resolver");
			dc_c = SPF_dns_cache_new(dc_r, NULL, debug, 8);
			if (dc_c == NULL)
				SPF_error("Failed to create DNS cache");
			sp->resolver = dc_c;
			break;

		case SPF_DNS_ZONE:
			dc_z = SPF_dns_zone_new(NULL, NULL, debug);
			if (dc_z == NULL)
				SPF_error("Failed to create DNS zone");
			sp->resolver = dc_z;
			break;

		default:
			SPF_errorf("Unknown DNS type %d", dnstype);
	}

	SPF_server_new_common_post(sp);

	return sp;
}

SPF_server_t *
SPF_server_new_dns(SPF_dns_server_t *dns, int debug)
{
	SPF_server_t	*sp;

	sp = (SPF_server_t *)malloc(sizeof(SPF_server_t));
	if (! sp)
		return sp;
	SPF_server_new_common_pre(sp, debug);
	sp->destroy_resolver = 0;
	sp->resolver = dns;
	SPF_server_new_common_post(sp);
	return sp;
}

/**
 * This function destroys the DNS layer as well.
 * If the (custom) DNS layer has no destructor,
 * then this cannot and does not destroy it.
 */
void
SPF_server_free(SPF_server_t *sp)
{
	if (sp->resolver && sp->destroy_resolver)
		SPF_dns_free(sp->resolver);
	if (sp->local_policy)
		SPF_record_free(sp->local_policy);
	if (sp->explanation)
		SPF_macro_free(sp->explanation);
	if (sp->rec_dom)
		free(sp->rec_dom);
	/* XXX TODO: Free other parts of the structure. */
	free(sp);
}

SPF_errcode_t
SPF_server_set_rec_dom(SPF_server_t *sp, const char *dom)
{
	if (sp->rec_dom)
		free(sp->rec_dom);
	if (dom == NULL)
		return SPF_server_set_rec_dom_ghbn(sp);
	sp->rec_dom = strdup(dom);
	if (! sp->rec_dom)
		return SPF_E_NO_MEMORY;
	return SPF_E_SUCCESS;
}

SPF_errcode_t
SPF_server_set_sanitize(SPF_server_t *sp, int sanitize)
{
	sp->sanitize = sanitize;
	return SPF_E_SUCCESS;
}

SPF_errcode_t
SPF_server_set_explanation(SPF_server_t *sp, const char *exp,
				SPF_response_t **spf_responsep)
{
	SPF_macro_t		*spf_macro = NULL;
	SPF_errcode_t	 err;

	SPF_ASSERT_NOTNULL(exp);

	/* This is a hackish way to get the errors. */
	if (! *spf_responsep) {
		*spf_responsep = SPF_response_new(NULL);
		if (! *spf_responsep)
			return SPF_E_NO_MEMORY;
	}

	err = SPF_record_compile_macro(sp, *spf_responsep, &spf_macro, exp);
	if (err == SPF_E_SUCCESS) {
		if (sp->explanation)
			SPF_macro_free(sp->explanation);
		sp->explanation = spf_macro;
	}
	else {
		SPF_response_add_error(*spf_responsep, err,
				"Failed to compile explanation '%s'", exp);
		if (spf_macro)
			SPF_macro_free(spf_macro);
	}

	return err;
}

SPF_errcode_t
SPF_server_set_localpolicy(SPF_server_t *sp, const char *policy,
				int use_default_whitelist,
				SPF_response_t **spf_responsep)
{
	SPF_record_t	*spf_record = NULL;
	SPF_errcode_t	 err;
	char			*record;
	size_t			 len;

	SPF_ASSERT_NOTNULL(policy);

	/* This is a hackish way to get the errors. */
	if (! *spf_responsep) {
		*spf_responsep = SPF_response_new(NULL);
		if (! *spf_responsep)
			return SPF_E_NO_MEMORY;
	}

	len = sizeof(SPF_VER_STR) + strlen(policy) + 20;
	if (use_default_whitelist)
		len += sizeof(SPF_DEFAULT_WHITELIST);
	record = malloc(len);
	if (! record)
		return SPF_E_NO_MEMORY;
	if (use_default_whitelist)
		snprintf(record, len, "%s %s %s",
						SPF_VER_STR, policy, SPF_DEFAULT_WHITELIST);
	else
		snprintf(record, len, "%s %s", SPF_VER_STR, policy);

	err = SPF_record_compile(sp, *spf_responsep, &spf_record, record);
	if (err == SPF_E_SUCCESS) {
		if (sp->local_policy)
			SPF_record_free(sp->local_policy);
		sp->local_policy = spf_record;
	}
	else {
		SPF_response_add_error(*spf_responsep, err,
				"Failed to compile local policy '%s'", policy);
		if (spf_record)
			SPF_record_free(spf_record);
	}

	free(record);

	return err;
}

SPF_errcode_t
SPF_server_get_record(SPF_server_t *spf_server,
				SPF_request_t *spf_request,
				SPF_response_t *spf_response,
				SPF_record_t **spf_recordp)
{
	SPF_dns_server_t		*resolver;
	SPF_dns_rr_t			*rr_txt;
	SPF_errcode_t			 err;
	SPF_dns_stat_t			 herrno;
	const char				*domain;
	ns_type					 rr_type;
	int						 num_found;
	int						 idx_found;
	int						 i;


	SPF_ASSERT_NOTNULL(spf_server);
	SPF_ASSERT_NOTNULL(spf_request);
	SPF_ASSERT_NOTNULL(spf_server->resolver);
	SPF_ASSERT_NOTNULL(spf_recordp);

	domain = spf_request->cur_dom;
	SPF_ASSERT_NOTNULL(domain);

	*spf_recordp = NULL;

	resolver = spf_server->resolver;

	if (resolver->get_spf)
		return resolver->get_spf(spf_server, spf_request,
						spf_response, spf_recordp);

	rr_type = ns_t_txt;
	rr_txt = SPF_dns_lookup(resolver, domain, rr_type, TRUE);

	switch (rr_txt->herrno) {
		case HOST_NOT_FOUND:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): HOST_NOT_FOUND", domain);
			SPF_dns_rr_free(rr_txt);
			spf_response->result = SPF_RESULT_NONE;
			spf_response->reason = SPF_REASON_FAILURE;
			return SPF_response_add_error(spf_response, SPF_E_NOT_SPF,
					"Host '%s' not found.", domain);
			// break;

		case NO_DATA:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): NO_DATA", domain);
			SPF_dns_rr_free(rr_txt);
			spf_response->result = SPF_RESULT_NONE;
			spf_response->reason = SPF_REASON_FAILURE;
			return SPF_response_add_error(spf_response, SPF_E_NOT_SPF,
					"No DNS data for '%s'.", domain);
			// break;

		case TRY_AGAIN:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): TRY_AGAIN", domain);
			SPF_dns_rr_free(rr_txt);
			spf_response->result = SPF_RESULT_TEMPERROR;
			spf_response->reason = SPF_REASON_FAILURE;
			return SPF_response_add_error(spf_response, SPF_E_DNS_ERROR,
					"Temporary DNS failure for '%s'.", domain);
			// break;

		case NO_RECOVERY:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): NO_RECOVERY", domain);
			SPF_dns_rr_free(rr_txt);
			spf_response->result = SPF_RESULT_PERMERROR;
			spf_response->reason = SPF_REASON_FAILURE;
			return SPF_response_add_error(spf_response, SPF_E_DNS_ERROR,
					"Unrecoverable DNS failure for '%s'.", domain);
			// break;

		case NETDB_SUCCESS:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): NETDB_SUCCESS", domain);
			break;

		default:
			if (spf_server->debug > 0)
				SPF_debugf("get_record(%s): UNKNOWN_ERROR", domain);
			herrno = rr_txt->herrno;	// Avoid use-after-free
			SPF_dns_rr_free(rr_txt);
			return SPF_response_add_error(spf_response, SPF_E_DNS_ERROR,
					"Unknown DNS failure for '%s': %d.",
					domain, herrno);
			// break;
	}

	if (rr_txt->num_rr == 0) {
		SPF_dns_rr_free(rr_txt);
		return SPF_response_add_error(spf_response, SPF_E_NOT_SPF,
				"No TXT records returned from DNS lookup for '%s'",
				domain);
	}

	/* Actually, this could never be used uninitialised anyway. */
	idx_found = 0;

	/* check for multiple SPF records */
	num_found = 0;
	for (i = 0; i < rr_txt->num_rr; i++) {
		/*
		if (spf_server->debug > 1)
			SPF_debugf("Comparing '%s' with '%s'",
					SPF_VER_STR " ", rr_txt->rr[i]->txt);
		*/
		if (strncasecmp(rr_txt->rr[i]->txt,
					  SPF_VER_STR, sizeof(SPF_VER_STR) - 1) == 0) {
			char	e = rr_txt->rr[i]->txt[sizeof(SPF_VER_STR) - 1];
			if (e == ' ' || e == '\0') {
				if (spf_server->debug > 0)
					SPF_debugf("found SPF record: %s", rr_txt->rr[i]->txt);
				num_found++;
				idx_found = i;
			}
		}
	}

	if (num_found == 0) {
		SPF_dns_rr_free(rr_txt);
		spf_response->result = SPF_RESULT_NONE;
		spf_response->reason = SPF_REASON_FAILURE;
		return SPF_response_add_error(spf_response, SPF_E_NOT_SPF,
				"No SPF records for '%s'", domain);
	}
	if (num_found > 1) {
		SPF_dns_rr_free(rr_txt);
		// rfc4408 requires permerror here.
		/* XXX This could be refactored with SPF_i_done. */
		spf_response->result = SPF_RESULT_PERMERROR;
		spf_response->reason = SPF_REASON_FAILURE;
		return SPF_response_add_error(spf_response, SPF_E_MULTIPLE_RECORDS,
				"Multiple SPF records for '%s'", domain);
	}

	/* try to compile the SPF record */
	err = SPF_record_compile(spf_server,
					spf_response, spf_recordp,
					rr_txt->rr[idx_found]->txt );
	SPF_dns_rr_free(rr_txt);

	/* FIXME: support multiple versions */
	if (err != SPF_E_SUCCESS)
		return SPF_response_add_error(spf_response, SPF_E_NOT_SPF,
				"Failed to compile SPF record for '%s'", domain);

	return SPF_E_SUCCESS;
}

/**
 * Various accessors.
 *
 * The user is permitted to override the maximums.
 */
#define SPF_ACCESS_INT(f) \
	SPF_errcode_t SPF_server_set_ ## f(SPF_server_t *s, int n) { \
		s->f = n; return SPF_E_SUCCESS; \
	} \
	int SPF_server_get_ ## f(SPF_server_t *s) { \
		return s->f; \
	}

/**
 * The return values from these getter functions are used without
 * modification. If you set a value higher than the specified
 * maximum, it will be used. Beware.
 */
SPF_ACCESS_INT(max_dns_mech);
SPF_ACCESS_INT(max_dns_ptr);
SPF_ACCESS_INT(max_dns_mx);
