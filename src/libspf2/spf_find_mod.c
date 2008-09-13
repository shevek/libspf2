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

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif


#include "spf.h"
#include "spf_internal.h"



#if 0

/* The RFC says this never happens. */

SPF_errcode_t
SPF_find_mod_cidr(SPF_server_t *spf_server,
		SPF_record_t *spf_record,
		const char *mod_name,
		int *ipv4_cidr, int *ipv6_cidr )
{
    SPF_data_t		*data;
    size_t		data_len;
    SPF_errcode_t	err;

    /*
     * make sure we were passed valid data to work with
     */
    SPF_ASSERT_NOTNULL(spf_record);
    SPF_ASSERT_NOTNULL(mod_name);
    SPF_ASSERT_NOTNULL(bufp);
    SPF_ASSERT_NOTNULL(buflenp);


    err = SPF_find_mod_data(spf_server, spf_record,
    				mod_name, &data, &data_len);
    if (err)
	return err;

    if ( data->dc.parm_type == PARM_CIDR )
    {
	*ipv4_cidr = data->dc.ipv4;
	*ipv6_cidr = data->dc.ipv6;
    } else {
	*ipv4_cidr = 0;
	*ipv6_cidr = 0;
    }
    
    return SPF_E_SUCCESS;
}
#endif
