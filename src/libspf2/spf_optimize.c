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



#include "spf.h"
#include "spf_internal.h"



int SPF_optimize( SPF_config_t spfcid, SPF_id_t *dst_spfid, SPF_id_t src_spfid )
{
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( src_spfid == NULL )
	SPF_error( "src_spfid is NULL" );



    /* FIXME  Actually do some optimizations here.... ;-> */
    *dst_spfid = SPF_dup_id( src_spfid );

    return SPF_E_SUCCESS;
}
