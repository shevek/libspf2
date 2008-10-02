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
# include <stdlib.h>	   /* malloc / free */
# include <stdio.h>		/* stdin / stdout */
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
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


	/* This never happens. We get SPF_DEFAULT_EXP instead.
	 * This is a panic response which must not contain macros. */
#define SPF_LAME_EXP	"SPF failure: no explanation available"

static SPF_errcode_t
SPF_server_get_default_explanation(SPF_server_t *spf_server,
						SPF_request_t *spf_request,
						SPF_response_t *spf_response,
						char **bufp, size_t *buflenp)
{
	SPF_errcode_t		 err;
	SPF_macro_t			*spf_macro;

	spf_macro = spf_server->explanation;
	if (spf_macro != NULL) {
		err = SPF_record_expand_data(spf_server,
						spf_request, spf_response,
						SPF_macro_data(spf_macro), spf_macro->macro_len,
						bufp, buflenp);
		return err;
	}
	else {
		size_t	len = sizeof(SPF_LAME_EXP) + 1;
		if (*buflenp < len) {
			char	*tmp = realloc(*bufp, len);
			if (tmp == NULL)
				return SPF_E_NO_MEMORY;
			*bufp = tmp;
			*buflenp = len;
		}
		strcpy(*bufp, SPF_LAME_EXP);
		return SPF_E_SUCCESS;
	}
}

#define RETURN_DEFAULT_EXP() do { \
		return SPF_server_get_default_explanation(spf_server, \
						spf_request, spf_response, bufp, buflenp); \
				} while(0)

SPF_errcode_t
SPF_request_get_exp(SPF_server_t *spf_server,
						SPF_request_t *spf_request,
						SPF_response_t *spf_response,
						SPF_record_t *spf_record,
						char **bufp, size_t *buflenp)
{
	SPF_macro_t			*spf_macro;
	SPF_dns_server_t	*resolver;
	SPF_dns_rr_t		*rr_txt;
	SPF_errcode_t		 err;
	const char			*domain;


	/*
	 * There are lots of places to look for the explanation message,
	 * some require DNS lookups, some don't.
	 */

	SPF_ASSERT_NOTNULL(spf_server);
	SPF_ASSERT_NOTNULL(spf_request);
	SPF_ASSERT_NOTNULL(spf_response);
	SPF_ASSERT_NOTNULL(spf_record);
	SPF_ASSERT_NOTNULL(bufp);
	SPF_ASSERT_NOTNULL(buflenp);

	domain = spf_request->cur_dom;

	if ( domain == NULL )
		return SPF_response_add_warn(spf_response, SPF_E_NOT_CONFIG,
				"Could not identify current domain for explanation");

	/*
	 * start looking...  check spfid for exp-text=
	 */

	err = SPF_record_find_mod_value(spf_server, spf_request,
					spf_response, spf_record,
					SPF_EXP_MOD_NAME, bufp, buflenp);
	if (err == SPF_E_SUCCESS)
		return err;


	/*
	 * still looking...  check the spfid for exp=
	 */

	err = SPF_record_find_mod_value(spf_server, spf_request,
					spf_response, spf_record,
					"exp", bufp, buflenp );
	if (err != SPF_E_SUCCESS) {
		/*
		 * still looking...  try to return default exp from spfcid
		 */
		RETURN_DEFAULT_EXP();
	}

	if (*bufp == NULL  ||  (*bufp)[0] == '\0') {
		/*
		 * still looking...  try to return default exp from spfcid
		 */
		SPF_response_add_warn(spf_response, SPF_E_NOT_SPF,
						"Explanation is blank!");
		RETURN_DEFAULT_EXP();
	}


	/*
	 * still looking...  try doing a DNS lookup on the exp= name
	 */

	resolver = spf_server->resolver;

	if (resolver->get_exp)
		return resolver->get_exp(spf_server, *bufp, bufp, buflenp);

	rr_txt = SPF_dns_lookup(resolver, *bufp, ns_t_txt, TRUE);
	if (rr_txt == NULL) {
		SPF_dns_rr_free(rr_txt);
		RETURN_DEFAULT_EXP();
	}

	switch (rr_txt->herrno) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			SPF_dns_rr_free(rr_txt);
			RETURN_DEFAULT_EXP();
			break;

		case TRY_AGAIN:
			SPF_dns_rr_free(rr_txt);
			RETURN_DEFAULT_EXP();
			break;

		case NETDB_SUCCESS:
			break;

		default:
			SPF_warning("Unknown DNS lookup error code");
			SPF_dns_rr_free(rr_txt);
			RETURN_DEFAULT_EXP();
			break;
	}

	if (rr_txt->num_rr == 0) {
		SPF_response_add_warn(spf_response, SPF_E_NOT_SPF,
				"No TXT records returned from DNS lookup");
		RETURN_DEFAULT_EXP();
	}


	/*
	 * still looking...  try compiling this TXT record
	 */

	/* FIXME  we are supposed to concatenate the TXT records */

	/* FIXME: If this generates any errors, demote them to warnings. */
	spf_macro = NULL;
	err = SPF_record_compile_macro(spf_server, spf_response, &spf_macro,
								rr_txt->rr[0]->txt);
	if (err != SPF_E_SUCCESS) {
		if (spf_macro)
			SPF_macro_free(spf_macro);
		SPF_dns_rr_free(rr_txt);
		RETURN_DEFAULT_EXP();
	}

	err = SPF_record_expand_data(spf_server,
					spf_request, spf_response,
					SPF_macro_data(spf_macro), spf_macro->macro_len,
					bufp, buflenp);
	SPF_macro_free(spf_macro);
	SPF_dns_rr_free(rr_txt);

	return err;
}
