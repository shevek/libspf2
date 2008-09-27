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
# include <ctype.h>		/* isupper / tolower */
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>	   /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>	   /* strstr / strdup */
# endif
#endif



#include "spf.h"
#include "spf_internal.h"
#include "spf_record.h"


#define SPF_MSGSIZE		4096


SPF_record_t *
SPF_record_new(SPF_server_t *spf_server, const char *text)
{
	SPF_record_t	*rp;
	
	rp = (SPF_record_t *)malloc(sizeof(SPF_record_t));
	if (!rp)
		return rp;
	memset(rp, 0, sizeof(SPF_record_t));

	rp->spf_server = spf_server;

	return rp;
}

void
SPF_record_free(SPF_record_t *rp)
{
	if (rp->mech_first)
		free(rp->mech_first);
	if (rp->mod_first)
		free(rp->mod_first);
	free(rp);
}

void
SPF_macro_free(SPF_macro_t *mac)
{
	free(mac);
}

/* This expects datap and datalenp NOT to be initialised. */
static SPF_errcode_t
SPF_record_find_mod_data(
		SPF_record_t *spf_record,
		const char *mod_name,
		SPF_data_t **datap, size_t *datalenp)
{
	SPF_mod_t	*mod;
	size_t		name_len;
	int			i;

	name_len = strlen( mod_name );

	/*
	 * make sure we were passed valid data to work with
	 */
	SPF_ASSERT_NOTNULL(spf_record);
	SPF_ASSERT_NOTNULL(mod_name);
	SPF_ASSERT_NOTNULL(datap);
	SPF_ASSERT_NOTNULL(datalenp);

	/*
	 * find modifier
	 */

	mod = spf_record->mod_first;
	for( i = 0; i < spf_record->num_mod; i++ ) {
		if ( name_len == mod->name_len
			 && strncasecmp( SPF_mod_name( mod ), mod_name, name_len ) == 0 )
		{
			*datap = SPF_mod_data( mod );
			*datalenp = mod->data_len;

			return 0;
		}
		
		mod = SPF_mod_next( mod );
	}
	
	return SPF_E_MOD_NOT_FOUND;
}

/* Nota Bene: *datap and *datalenp MUST BE INITIALIZED, possibly to
 * NULL. SPF_record_expand_data requires this. I do not strictly
 * approve, but
 * I guess it makes things easier on the allocator? It clouds the
 * issue of responsibility for memory. */
SPF_errcode_t
SPF_record_find_mod_value(SPF_server_t *spf_server,
		SPF_request_t *spf_request,
		SPF_response_t *spf_response,
		SPF_record_t *spf_record,
		const char *mod_name,
		char **bufp, size_t *buflenp)
{
	SPF_data_t		*data;
	size_t		 data_len;
	SPF_errcode_t	 err;

	/*
	 * make sure we were passed valid data to work with
	 */
	SPF_ASSERT_NOTNULL(spf_record);
	SPF_ASSERT_NOTNULL(mod_name);
	SPF_ASSERT_NOTNULL(bufp);
	SPF_ASSERT_NOTNULL(buflenp);

	err = SPF_record_find_mod_data(spf_record,
					mod_name, &data, &data_len);
	if (err)
		return err;

	return SPF_record_expand_data(spf_server, spf_request, spf_response,
					data, data_len, bufp, buflenp);
}
