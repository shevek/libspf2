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
# include <stdlib.h>       /* malloc / free */
#endif


#include "spf.h"
#include "spf_internal.h"



/* TODO: FIXME: Replace this function. */
#if 0
SPF_err_t SPF_verify( SPF_config_t spfcid, SPF_id_t spfid )
{
    SPF_id_t	spfid_new;
    SPF_c_results_t c_results;
    char	*spf_rec = NULL;
    size_t	spf_rec_len;
    SPF_err_t	err;
    

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );


    /* FIXME  SPF_verify()
     *
     * * Checks that should be done
     *   * maybe SPF_verify should be SPF_id2str with a null buffer?
     * 
     *   * version ok
     *   * lengths ok
     *   * counts ok
     *   * types ok
     *   * max_dns_mech
     *   * cidr data first and not both zero
     *   * ip4/ip6 cidr ranges
     *   * invalid chars in data_str and mod name
     *   * data on mechs that shouldn't have any
     *   * mechs that should have data, but don't
     */

    err =  SPF_id2str( &spf_rec, &spf_rec_len, spfid );

    if ( err )
    {
	if ( spf_rec ) free( spf_rec );
	return err;
    }

    if ( spf_rec == NULL )
	return SPF_E_INTERNAL_ERROR;

    spfid_new = SPF_create_id();
    if ( spfid_new == NULL )
    {
	free( spf_rec );
	return SPF_E_NO_MEMORY;
    }
    
    SPF_init_c_results( &c_results );

    err = SPF_compile( spfcid, spf_rec, &c_results );

    SPF_free_c_results( &c_results );
    free( spf_rec );

    return err;
}
#endif
