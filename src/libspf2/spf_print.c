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




void SPF_print( SPF_id_t spfid )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);
    char	*prt_buf = NULL;
    size_t	prt_len = 0;

    int		err;

    /*
     * make sure we were passed valid data to work with
     */
    if ( spfi == NULL )
	SPF_error( "spfid is NULL" );
    
    SPF_infof( "SPF header:  version: %d  mech %d/%d  mod %d/%d  len=%d",
	    spfi->header.version,
	    spfi->header.num_mech, spfi->header.mech_len, 
	    spfi->header.num_mod, spfi->header.mod_len,
	    sizeof(spfi->header) + spfi->header.mech_len
	    + spfi->header.mod_len);

    err = SPF_id2str( &prt_buf, &prt_len, spfid );
    if ( err == SPF_E_RESULT_UNKNOWN )
	SPF_info( "Unknown" );
    else if ( err )
	SPF_infof( "SPF_id2str error: %s (%d)", SPF_strerror( err ), err );
    else
	SPF_infof( "SPF record:  %s", prt_buf );

    if ( prt_buf )
	free( prt_buf );
	    
}





void SPF_print_sizeof(void)
{
    SPF_infof( "sizeof(SPF_rec_header_t)=%u", sizeof(SPF_rec_header_t));
    SPF_infof( "sizeof(SPF_mech_t)=%u", sizeof(SPF_mech_t));
    SPF_infof( "sizeof(SPF_data_t)=%u", sizeof(SPF_data_t));
    SPF_infof( "sizeof(SPF_mod_t)=%u", sizeof(SPF_mod_t));
}
