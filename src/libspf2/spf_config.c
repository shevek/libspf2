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
#endif

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif


#include "spf.h"
#include "spf_internal.h"


static SPF_c_results_t	SPF_default_whitelist;
static SPF_c_results_t	SPF_default_exp;
static char		*SPF_default_rec_dom;
		



SPF_config_t SPF_create_config() 
{
    SPF_iconfig_t *spfic;
        
    spfic = calloc( 1, sizeof(*spfic) );
    if ( spfic ) 
	SPF_reset_config( SPF_spfic2cid(spfic) );

    return SPF_spfic2cid(spfic);
}

void SPF_reset_config( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);


    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    spfic->client_ver = AF_UNSPEC;
    spfic->ipv4.s_addr = htonl( INADDR_ANY );
    spfic->ipv6 = in6addr_any;

    if ( spfic->env_from ) free( spfic->env_from );
    spfic->env_from = NULL;
    
    if ( spfic->helo_dom ) free( spfic->helo_dom );
    spfic->helo_dom = NULL;
    
    if ( spfic->rec_dom ) free( spfic->rec_dom );
    spfic->rec_dom = NULL;
    if ( SPF_default_rec_dom == NULL )
    {
	SPF_default_rec_dom = malloc( HOST_NAME_MAX );
	gethostname( SPF_default_rec_dom, HOST_NAME_MAX );
    }
    if ( SPF_default_rec_dom != NULL )
	spfic->rec_dom = strdup( SPF_default_rec_dom );

    /* if ( spfic->rcpt_to_dom ) free( spfic->rcpt_to_dom ); */
    spfic->rcpt_to_dom = NULL;		/* not malloced			*/
    spfic->found_2mx = FALSE;
    spfic->found_non_2mx = FALSE;
    SPF_free_output( &spfic->output_2mx );

    spfic->max_dns_mech = SPF_DEFAULT_MAX_DNS_MECH;
    spfic->max_dns_ptr = SPF_DEFAULT_MAX_DNS_PTR;
    spfic->max_dns_mx = SPF_DEFAULT_MAX_DNS_MX;
    spfic->sanitize = SPF_DEFAULT_SANITIZE;
    spfic->debug = 0;

    if ( spfic->lp_from ) free( spfic->lp_from );
    spfic->lp_from = NULL;
	
    if ( spfic->dp_from ) free( spfic->dp_from );
    spfic->dp_from = NULL;

    if ( spfic->cur_dom ) free( spfic->cur_dom );
    spfic->cur_dom = NULL;

    if ( spfic->client_dom ) free( spfic->client_dom );
    spfic->client_dom = NULL;

    /* must be always dealt with last because compiling uses the config */
    if ( SPF_default_whitelist.spfid == NULL
	 && SPF_default_whitelist.err == SPF_E_SUCCESS )
    {
	SPF_compile( spfcid, SPF_VER_STR " " SPF_DEFAULT_WHITELIST,
		     &SPF_default_whitelist );
    }
    spfic->local_policy = SPF_default_whitelist;

    if ( SPF_default_exp.spfid == NULL
	 && SPF_default_exp.err == SPF_E_SUCCESS )
    {
	SPF_compile_exp( spfcid, SPF_DEFAULT_EXP, &SPF_default_exp );
    }
    spfic->exp = SPF_default_exp;


    spfic->max_var_len = 0;		/* FIXME: this never shrinks	*/
}
    
void SPF_destroy_config( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    SPF_reset_config( spfcid );
    if ( spfic->rec_dom ) free( spfic->rec_dom ); /* gets realloc on reset */
    free( spfic );
}

SPF_config_t SPF_dup_config( SPF_config_t src_spfcid )
{
    SPF_iconfig_t	*src_spfic = SPF_cid2spfic( src_spfcid );
    SPF_config_t	dst_spfcid;
    SPF_iconfig_t	*dst_spfic;

    if ( src_spfcid == NULL )
	SPF_error( "src_spfcid is NULL" );


    dst_spfcid = SPF_create_config();
    dst_spfic = SPF_cid2spfic( dst_spfcid );

    if ( dst_spfic )
    {

	dst_spfic->client_ver = src_spfic->client_ver;
	dst_spfic->ipv4 = src_spfic->ipv4;
	dst_spfic->ipv6 = src_spfic->ipv6;

	if ( src_spfic->env_from )
	{
	    dst_spfic->env_from = strdup( src_spfic->env_from );
	    if ( !dst_spfic->env_from )
		goto error;
	}
	
	if ( src_spfic->helo_dom )
	{
	    dst_spfic->helo_dom = strdup( src_spfic->helo_dom );
	    if ( !dst_spfic->helo_dom )
		goto error;
	}
    
	if ( src_spfic->rec_dom )
	{
	    dst_spfic->rec_dom = strdup( src_spfic->rec_dom );
	    if ( !dst_spfic->rec_dom )
		goto error;
	}
    
	if ( src_spfic->rcpt_to_dom )
	{
	    dst_spfic->rcpt_to_dom = strdup( src_spfic->rcpt_to_dom );
	    if ( !dst_spfic->rcpt_to_dom )
		goto error;
	}
	dst_spfic->found_2mx = src_spfic->found_2mx;
	dst_spfic->found_non_2mx = src_spfic->found_non_2mx;
	dst_spfic->output_2mx = SPF_dup_output( src_spfic->output_2mx );

	dst_spfic->max_dns_mech = src_spfic->max_dns_mech;
	dst_spfic->max_dns_ptr = src_spfic->max_dns_ptr;
	dst_spfic->max_dns_mx = src_spfic->max_dns_mx;
	dst_spfic->sanitize = src_spfic->sanitize;
	dst_spfic->debug = src_spfic->debug;

	/* note:  these two spfid variable's allocation are controlled
	 *        by calling routines and can only be freed when all
	 *        configs that use them are freed
	 */
	dst_spfic->local_policy = src_spfic->local_policy;
	dst_spfic->exp = src_spfic->exp;

	if ( src_spfic->lp_from )
	{
	    dst_spfic->lp_from = strdup( src_spfic->lp_from );
	    if ( !dst_spfic->lp_from )
		goto error;
	}
    
	if ( src_spfic->dp_from )
	{
	    dst_spfic->dp_from = strdup( src_spfic->dp_from );
	    if ( !dst_spfic->dp_from )
		goto error;
	}
    
	if ( src_spfic->cur_dom )
	{
	    dst_spfic->cur_dom = strdup( src_spfic->cur_dom );
	    if ( !dst_spfic->cur_dom )
		goto error;
	}
    
	if ( src_spfic->client_dom )
	{
	    dst_spfic->client_dom = strdup( src_spfic->client_dom );
	    if ( !dst_spfic->client_dom )
		goto error;
	}


	dst_spfic->max_var_len = src_spfic->max_var_len;
    }
    
    return dst_spfcid;

  error:
    
    SPF_destroy_config( dst_spfcid );
    return NULL;

}

void SPF_destroy_default_config()
{
    SPF_free_c_results( &SPF_default_whitelist );
    SPF_free_c_results( &SPF_default_exp );
    if ( SPF_default_rec_dom ) free( SPF_default_rec_dom );
    SPF_default_rec_dom = NULL;
}





int SPF_set_ip_str( SPF_config_t spfcid, const char *ip_address )
{
    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( ip_address == NULL )
	ip_address = "0.0.0.0";

    if ( strchr( ip_address, ':' ) )
	return SPF_set_ipv6_str( spfcid, ip_address );
    else
	return SPF_set_ipv4_str( spfcid, ip_address );
}

int SPF_set_ipv4_str( SPF_config_t spfcid, const char *ipv4_address )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( ipv4_address == NULL )
	ipv4_address = "0.0.0.0";

    if ( spfic->client_dom ) free( spfic->client_dom );
    spfic->client_dom = NULL;
    spfic->found_2mx = FALSE;
    spfic->found_non_2mx = FALSE;

    spfic->client_ver = AF_INET;
    return inet_pton( AF_INET, ipv4_address, &spfic->ipv4) <= 0;
}

int SPF_set_ipv6_str( SPF_config_t spfcid, const char *ipv6_address )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    int		err;

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( ipv6_address == NULL )
	ipv6_address = "::";

    if ( spfic->client_dom ) free( spfic->client_dom );
    spfic->client_dom = NULL;
    spfic->found_2mx = FALSE;
    spfic->found_non_2mx = FALSE;

    spfic->client_ver = AF_INET6;
    err = inet_pton( AF_INET6, ipv6_address, &spfic->ipv6) <= 0;
    if ( err )
	return err;
    
    if ( IN6_IS_ADDR_V4MAPPED( &spfic->ipv6 ) )
    {
	struct in_addr ipv4;

	memcpy( &ipv4, &spfic->ipv6.s6_addr[12], sizeof( ipv4 ) );
	return SPF_set_ipv4( spfcid, ipv4 );
    }

    return err;
}


int SPF_set_ipv4( SPF_config_t spfcid, struct in_addr ipv4 )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->client_dom ) free( spfic->client_dom );
    spfic->client_dom = NULL;
    spfic->found_2mx = FALSE;
    spfic->found_non_2mx = FALSE;

    spfic->client_ver = AF_INET;
    spfic->ipv4 = ipv4;
    return 0;
}

int SPF_set_ipv6( SPF_config_t spfcid, struct in6_addr ipv6 )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->client_dom ) free( spfic->client_dom );
    spfic->client_dom = NULL;
    spfic->found_2mx = FALSE;
    spfic->found_non_2mx = FALSE;

    spfic->client_ver = AF_INET6;
    spfic->ipv6 = ipv6;
    return 0;
}


int SPF_set_env_from( SPF_config_t spfcid, const char *envelope_from )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    char	*pos;
    size_t	len;

    /* FIXME: validate charset/format  (local-part will be a bitch)*/

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );


    if ( spfic->env_from ) free( spfic->env_from );
    spfic->env_from = NULL;

    if ( envelope_from == NULL || *envelope_from == '\0' )
    {
	if ( spfic->helo_dom )
	    envelope_from = spfic->helo_dom;
	else
	    return 0;
    }
    
    spfic->env_from = strdup( envelope_from );
    if ( spfic->env_from == NULL )
	return 1;

    len = strlen( envelope_from );
    if ( spfic->max_var_len < len ) spfic->max_var_len = len;
    
    if ( spfic->lp_from ) free( spfic->lp_from );
    if ( spfic->dp_from ) free( spfic->dp_from );
    if ( spfic->cur_dom ) free( spfic->cur_dom );


    /* FIXME is this supposed to be the last @ sign? */
    pos = strrchr( spfic->env_from, '@' );
    if ( pos == NULL )
    {
	
	spfic->lp_from = strdup( "postmaster" );
	spfic->dp_from = strdup( spfic->env_from );
	spfic->cur_dom = strdup( spfic->env_from );
	free( spfic->env_from );
	len = sizeof( "postmaster@" ) + strlen( spfic->dp_from );
	spfic->env_from = malloc( len );
	if ( spfic->env_from )
	    snprintf( spfic->env_from, len, "postmaster@%s", spfic->dp_from );
    } else {
	spfic->lp_from = malloc( pos - spfic->env_from + 1 );
	if ( spfic->lp_from )
	{
	    memcpy( spfic->lp_from, spfic->env_from,
		    pos - spfic->env_from );
	    spfic->lp_from[ pos - spfic->env_from ] = '\0';
	}
	spfic->dp_from = strdup( pos + 1 );
	spfic->cur_dom = strdup( pos + 1 );
    }

    
    if ( spfic->env_from == NULL
	 || spfic->lp_from == NULL
	 || spfic->dp_from == NULL
	 || spfic->cur_dom == NULL)
    {
	free( spfic->env_from );
	spfic->env_from = NULL;

	if ( spfic->lp_from ) free( spfic->lp_from );
	spfic->lp_from = NULL;
	
	if ( spfic->dp_from ) free( spfic->dp_from );
	spfic->dp_from = NULL;

	if ( spfic->cur_dom ) free( spfic->cur_dom );
	spfic->cur_dom = NULL;

	return 1;
    }
    
    return 0;
}


int SPF_set_helo_dom( SPF_config_t spfcid, const char *helo_domain )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    size_t	len;

    /* FIXME: validate charset/format */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->helo_dom ) free( spfic->helo_dom );
    spfic->helo_dom = NULL;
    if ( helo_domain == NULL )
	return 0;

    spfic->helo_dom = strdup( helo_domain );
    if ( spfic->helo_dom == NULL ) return 1;

    if ( spfic->cur_dom == NULL )
	spfic->cur_dom = strdup( spfic->helo_dom );

    if ( spfic->env_from == NULL )
	SPF_set_env_from( spfcid, spfic->helo_dom );

    len = strlen( helo_domain );
    if ( spfic->max_var_len < len ) spfic->max_var_len = len;
    
    return 0;
}


int SPF_set_cur_dom( SPF_config_t spfcid, const char *current_domain )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    size_t	len;

    /* FIXME: validate charset/format */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->cur_dom ) free( spfic->cur_dom );
    spfic->cur_dom = NULL;
    if ( current_domain == NULL )
	return 0;

    spfic->cur_dom = strdup( current_domain );
    if ( spfic->cur_dom == NULL ) return 1;

    len = strlen( current_domain );
    if ( spfic->max_var_len < len ) spfic->max_var_len = len;
    
    return 0;
}


int SPF_set_max_dns_mech( SPF_config_t spfcid, int max_dns_mech )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);


    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    /* If you want to go beyond the spec, you need to recompile the
     * the library. */
    if ( max_dns_mech > SPF_MAX_DNS_MECH ) 
    {
	spfic->max_dns_mech = SPF_MAX_DNS_MECH;
	return 1;
    }
    

    spfic->max_dns_mech = max_dns_mech;
    return 0;
}


int SPF_set_max_dns_ptr( SPF_config_t spfcid, int max_dns_ptr )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);


    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    /* If you want to go beyond the spec, you need to recompile the
     * the library. */
    if ( max_dns_ptr > SPF_MAX_DNS_PTR ) 
    {
	spfic->max_dns_ptr = SPF_MAX_DNS_PTR;
	return 1;
    }
    

    spfic->max_dns_ptr = max_dns_ptr;
    return 0;
}


int SPF_set_max_dns_mx( SPF_config_t spfcid, int max_dns_mx )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);


    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    /* If you want to go beyond the spec, you need to recompile the
     * the library. */
    if ( max_dns_mx > SPF_MAX_DNS_MX ) 
    {
	spfic->max_dns_mx = SPF_MAX_DNS_MX;
	return 1;
    }
    

    spfic->max_dns_mx = max_dns_mx;
    return 0;
}


int SPF_set_sanitize( SPF_config_t spfcid, int sanitize )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    /* FIXME: validate? */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    spfic->sanitize = sanitize;
    return 0;
}


int SPF_set_rec_dom( SPF_config_t spfcid, const char *receiving_hostname )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);
    size_t	len;

    /* FIXME: validate charset/format */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->rec_dom ) free( spfic->rec_dom );
    spfic->rec_dom = NULL;
    if ( receiving_hostname == NULL )
	return 0;
    spfic->rec_dom = strdup( receiving_hostname );
    if ( spfic->rec_dom == NULL ) return 1;

    len = strlen( receiving_hostname );
    if ( spfic->max_var_len < len ) spfic->max_var_len = len;
    
    return 0;
}


SPF_err_t SPF_compile_local_policy( SPF_config_t spfcid, const char *spf_record,
				int use_default_whitelist,
				SPF_c_results_t *c_results )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);

    char		*buf;
    size_t		len;

    SPF_err_t		err;
    
    

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( c_results == NULL )
	SPF_error( "c_results is NULL" );

    if ( spf_record == NULL  &&  !use_default_whitelist )
	return SPF_E_SUCCESS;
    
    if ( spf_record == NULL )
	spf_record = "";


    len = strlen( spf_record )
	+ sizeof( SPF_VER_STR " " SPF_DEFAULT_WHITELIST " " );
    buf = malloc( len );
    
    if ( use_default_whitelist )
	snprintf( buf, len, "%s %s %s",
		      SPF_VER_STR, spf_record, SPF_DEFAULT_WHITELIST );
    else if ( *spf_record != '\0' )
	snprintf( buf, len, "%s %s",
		      SPF_VER_STR, spf_record );

    err = SPF_compile( spfcid, buf, c_results );

    free( buf );
    
    if ( err  &&  c_results->spfid )
    {
	if ( spfic->debug > 0 )
	    SPF_warning( c_results->err_msg );

	return err;
    }
    
    return SPF_E_SUCCESS;
}


int SPF_set_local_policy( SPF_config_t spfcid,
			  SPF_c_results_t c_results )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    /* FIXME: validate local_policy? */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    spfic->local_policy = c_results;
    return 0;
}



SPF_err_t SPF_compile_exp( SPF_config_t spfcid, const char *exp, SPF_c_results_t *c_results )
{
    char	*spf_rec;
    SPF_err_t	err;
    size_t	len;
    char	*p;
    const char	*s;

    
#define SPF_EXP_MOD	SPF_VER_STR " " SPF_EXP_MOD_NAME "="

    len = strlen( exp );
    spf_rec = malloc( len * 2 + sizeof( SPF_EXP_MOD ) );
    if ( spf_rec == NULL )
	return SPF_E_NO_MEMORY;
	
    strcpy( spf_rec, SPF_EXP_MOD );
	
    p = spf_rec + sizeof( SPF_EXP_MOD ) - 1;
    s = exp;

    while( *s != '\0' )
    {
	if ( *s == ' ' )
	{
	    *p++ = '%';
	    *p++ = '_';
	}
	else
	    *p++ = *s;
	s++;
    }
    *p = *s;
    
    err = SPF_compile( spfcid, spf_rec, c_results );

    free( spf_rec );

    return err;
}

int SPF_set_exp( SPF_config_t spfcid, SPF_c_results_t c_results )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);

    /* FIXME: validate exp? */

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    spfic->exp = c_results;
    return 0;
}




int SPF_set_debug( SPF_config_t spfcid, int debug_level )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic(spfcid);

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    spfic->debug = debug_level;

    if ( spfic->debug > 0 )
    {
	if ( SPF_default_whitelist.err )
	    SPF_warning( SPF_default_whitelist.err_msg );

	if ( SPF_default_exp.err )
	    SPF_warning( SPF_default_exp.err_msg );
    }
    
    return 0;
}



int SPF_get_client_ver( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->client_ver;
}


struct in_addr SPF_get_ipv4( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );
    struct in_addr  any;

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->client_ver != AF_INET )
    {
	any.s_addr = htonl( INADDR_ANY ); 
	return any;
    }
    

    return spfic->ipv4;
}


struct in6_addr SPF_get_ipv6( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if ( spfic->client_ver != AF_INET6 )
	return in6addr_any;

    return spfic->ipv6;
}


char *SPF_get_env_from( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->env_from;
}


char *SPF_get_helo_dom( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->helo_dom;
}


char *SPF_get_cur_dom( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->cur_dom;
}


char *SPF_get_client_dom( SPF_config_t spfcid, SPF_dns_config_t spfdcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    if( spfic->client_dom == NULL )
	SPF_set_client_dom( spfcid, spfdcid );

    return spfic->client_dom;
}


int  SPF_get_max_dns_mech( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->max_dns_mech;
}


int  SPF_get_max_dns_ptr( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->max_dns_ptr;
}


int  SPF_get_max_dns_mx( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->max_dns_mx;
}


int  SPF_get_sanitize( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->sanitize;
}


char *SPF_get_rec_dom( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->rec_dom;
}


SPF_c_results_t SPF_get_local_policy( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->local_policy;
}


int  SPF_get_debug( SPF_config_t spfcid )
{
    SPF_iconfig_t *spfic = SPF_cid2spfic( spfcid );

    if ( spfcid == NULL )
	SPF_error( "spfcid is NULL" );

    return spfic->debug;
}

