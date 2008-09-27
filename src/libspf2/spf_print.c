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

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif


#include "spf.h"
#include "spf_internal.h"



SPF_errcode_t
SPF_record_print(SPF_record_t *spf_record)
{
    char	*prt_buf = NULL;
    size_t	 prt_len = 0;
    int		 err;

	if (spf_record == NULL) {
		SPF_info("SPF header: <null record>");
		SPF_info("Unknown");
		return SPF_E_SUCCESS;
	}

    SPF_infof( "SPF header:  version: %d  mech %d/%u  mod %d/%u  len=%u",
	    spf_record->version,
	    (int)spf_record->num_mech, (unsigned int)spf_record->mech_len, 
	    (int)spf_record->num_mod, (unsigned int)spf_record->mod_len,
	    (unsigned int)(sizeof(SPF_record_t)
				+ spf_record->mech_len
				+ spf_record->mod_len));

    err = SPF_record_stringify(spf_record, &prt_buf, &prt_len);
    if ( err == SPF_E_RESULT_UNKNOWN )
	SPF_info( "Unknown" );
    else if ( err )
	SPF_infof( "SPF_record_stringify error: %s (%d)", SPF_strerror( err ), err );
    else
	SPF_infof( "SPF record:  %s", prt_buf );

    if ( prt_buf )
		free( prt_buf );
	return SPF_E_SUCCESS;
}





void SPF_print_sizeof(void)
{
    // SPF_infof( "sizeof(SPF_rec_header_t)=%u", sizeof(SPF_rec_header_t));
    SPF_infof( "sizeof(SPF_mech_t)=%lu", (unsigned long)sizeof(SPF_mech_t));
    SPF_infof( "sizeof(SPF_data_t)=%lu", (unsigned long)sizeof(SPF_data_t));
    SPF_infof( "sizeof(SPF_mod_t)=%lu", (unsigned long)sizeof(SPF_mod_t));
}
