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
# include <ctype.h>        /* isupper / tolower */
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif



#include "spf.h"
#include "spf_internal.h"



SPF_id_t SPF_create_id() 
{
    SPF_internal_t *spfi;
        
    spfi = calloc( 1, sizeof(*spfi) );
    if ( spfi )
	SPF_reset_id( SPF_spfi2id(spfi) );

    return SPF_spfi2id(spfi);
}

void SPF_reset_id( SPF_id_t spfid )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );

    if (spfi->mech_first)
	free( spfi->mech_first );
    if (spfi->mod_first)
	free( spfi->mod_first );

    spfi->mech_first = NULL;
    spfi->mech_last = NULL;
    spfi->mech_buf_len = 0;
    spfi->mod_first = NULL;
    spfi->mod_last = NULL;
    spfi->mod_buf_len = 0;
    
    spfi->header.version = 1;
    spfi->header.num_mech = 0;
    spfi->header.num_mod = 0;
    spfi->header.mech_len = 0;
    spfi->header.mod_len = 0;
}
    
void SPF_destroy_id( SPF_id_t spfid )
{
    SPF_internal_t *spfi = SPF_id2spfi(spfid);

    if ( spfid == NULL )
	SPF_error( "spfid is NULL" );

    SPF_reset_id( spfid );
    free( spfi );
}

SPF_id_t SPF_dup_id( SPF_id_t src_spfid )
{
    SPF_internal_t	*src_spfi = SPF_id2spfi( src_spfid );
    SPF_id_t		dst_spfid;
    SPF_internal_t	*dst_spfi;
        
    if ( src_spfid == NULL )
	SPF_error( "src_spfid is NULL" );

    dst_spfid = SPF_create_id();
    dst_spfi = SPF_id2spfi( dst_spfid );

    if ( dst_spfi )
    {
	dst_spfi->header = src_spfi->header;

	if (src_spfi->mech_first)
	{
	    dst_spfi->mech_buf_len = src_spfi->mech_buf_len;
	    dst_spfi->mech_first = malloc( dst_spfi->mech_buf_len );
	    if ( dst_spfi->mech_first == NULL )
	    {
		SPF_destroy_id( dst_spfid );
		return NULL;
	    }
	    memcpy( dst_spfi->mech_first, src_spfi->mech_first,
		    dst_spfi->mech_buf_len );
	}

	if (src_spfi->mod_first)
	{
	    dst_spfi->mod_buf_len = src_spfi->mod_buf_len;
	    dst_spfi->mod_first = malloc( dst_spfi->mod_buf_len );
	    if ( dst_spfi->mod_first == NULL )
	    {
		SPF_destroy_id( dst_spfid );
		return NULL;
	    }
	    memcpy( dst_spfi->mod_first, src_spfi->mod_first,
		    dst_spfi->mod_buf_len );
	}

	dst_spfi->mech_last = dst_spfi->mech_first
	    + (src_spfi->mech_last - src_spfi->mech_first);
	dst_spfi->mod_last = dst_spfi->mod_first
	    + (src_spfi->mod_last - src_spfi->mod_first);
    
    }
    return dst_spfid;
}


void SPF_get_lib_version( int *major, int *minor, int *patch )
{
    *major = SPF_LIB_VERSION_MAJOR;
    *minor = SPF_LIB_VERSION_MINOR;
    *patch = SPF_LIB_VERSION_PATCH;
}






char *SPF_sanitize( SPF_config_t spfcid, char *str )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    char *p = str;
    

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( !spfic->sanitize )
	return str;

    if ( str == NULL )
	return str;
    
    for( p = str; *p != '\0'; p++ )
	if ( !isprint( (unsigned char)*p ) )
	    *p = '?';

    return str;
}



int SPF_is_loopback( SPF_config_t spfcid )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    
    if ( spfic->client_ver == AF_INET )
    {
	if ( (ntohl( spfic->ipv4.s_addr ) & IN_CLASSA_NET) == (IN_LOOPBACKNET<<24) )
	    return TRUE;
    }
    else if ( spfic->client_ver == AF_INET6 )
    {
	if ( IN6_IS_ADDR_LOOPBACK( &spfic->ipv6 ) )
	    return TRUE;
    }
    return FALSE;
}



