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




SPF_err_t SPF_find_mod_data( SPF_config_t spfcid, SPF_id_t spfid, const char *mod_name,
		       SPF_data_t **data, size_t *data_len )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);
    int		i;
    SPF_mod_t	*mod;
    size_t	name_len = strlen( mod_name );

    /*
     * make sure we were passed valid data to work with
     */
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );
    

    /*
     * find modifier
     */

    mod = spfi->mod_first;
    for( i = 0; i < spfi->header.num_mod; i++ )
    {
	if ( name_len == mod->name_len
	     && strncmp( SPF_mod_name( mod ), mod_name, mod->name_len ) == 0 )
	{
	    *data = SPF_mod_data( mod );
	    *data_len = mod->data_len;

	    return 0;
	}
    
	mod = SPF_next_mod( mod );
    }
    
    return 1;
}


SPF_err_t SPF_find_mod_value( SPF_config_t spfcid, SPF_id_t spfid,
			SPF_dns_config_t spfdc, const char *mod_name,
			char **buf, size_t *buf_len )
{
    SPF_data_t	*data;
    size_t	data_len;
    SPF_err_t	err;

    /*
     * make sure we were passed valid data to work with
     */
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );
    
    if ( spfdc == NULL )
	SPF_error( "spfdc is NULL" );


    err = SPF_find_mod_data( spfcid, spfid, mod_name, &data, &data_len );

    if ( err )
	return SPF_E_MOD_NOT_FOUND;

    return SPF_expand( spfcid, spfdc, data, data_len, buf, buf_len );
}


SPF_err_t SPF_find_mod_cidr( SPF_config_t spfcid, SPF_id_t spfid,
			     SPF_dns_config_t spfdc, const char *mod_name,
			     int *ipv4_cidr, int *ipv6_cidr )
{
    SPF_data_t	*data;
    size_t	data_len;
    SPF_err_t	err;

    /*
     * make sure we were passed valid data to work with
     */
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );
    
    if ( spfdc == NULL )
	SPF_error( "spfdc is NULL" );


    err = SPF_find_mod_data( spfcid, spfid, mod_name, &data, &data_len );

    if ( err )
	return SPF_E_MOD_NOT_FOUND;

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


