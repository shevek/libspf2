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




/*
 * NOTE:
 *
 * This is just a text bed that can be used while developing the
 * library.  It is not intended to make sense or to be useful.
 */

#define SPF_TEST_VERSION  "2.0"


/* we include spf_internal.h so us internal config.h */
#include "spf_sys_config.h"


#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>       /* malloc / free */
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>    /* types (u_char .. etc..) */
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

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>    /* in_addr struct */
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>    /* in_addr struct */
#endif



#include "spf.h"
#include "spf_dns.h"
#include "spf_dns_test.h"

#include "spf_dns_internal.h"	/* we test the lookup functions	*/


#define TRUE 1
#define FALSE 0



static void usage()
{
    printf( "Usage: spftest [spf \"<spf record>\" | domain <domain name>\n" );
    printf( "                | ip <ip address> | exp \"<explanation string>\"\n" );
    printf( "                | version ]\n" );
}


int main( int argc, char *argv[] )
{
    SPF_config_t	spfcid = NULL;
    SPF_dns_config_t	spfdcid = NULL;
    SPF_c_results_t	c_results;

    char		*spf_rec;
    SPF_dns_rr_t	*dns_rr;
    
    int		err;
    int	 major, minor, patch;
    
    SPF_init_c_results( &c_results );

/*    SPF_print_sizeof(); */
    spfcid = SPF_create_config();
    if ( spfcid == NULL )
    {
	printf( "SPF_dns_create_config_test failed.\n" );
	err = 1;
	goto error;
    }
    SPF_set_debug( spfcid, 999 );
    

    spfdcid = SPF_dns_create_config_test( NULL );
    if ( spfdcid == NULL )
    {
	printf( "SPF_dns_create_config_test failed.\n" );
	err = 1;
	goto error;
    }
    

    if ( argc <= 1 )
    {
	usage();
	err = 1;
	goto error;
    }

    if ( strcmp( argv[1], "version" ) == 0 )
    {
	fprintf( stderr, "spftest version information:\n" );
	fprintf( stderr, "SPF test system version: %s\n",
		 SPF_TEST_VERSION );
	fprintf( stderr, "Compiled with SPF library version: %d.%d.%d\n",
		 SPF_LIB_VERSION_MAJOR, SPF_LIB_VERSION_MINOR,
		 SPF_LIB_VERSION_PATCH );
	SPF_get_lib_version( &major, &minor, &patch );
	fprintf( stderr, "Running with SPF library version: %d.%d.%d\n",
		 major, minor, patch );
	fprintf( stderr, "\n" );
	err = 0;
	goto error;
    }
    
    if ( argc <= 2 )
    {
	usage();
	err = 1;
	goto error;
    }
    else if ( strcmp( argv[1], "spf" ) == 0 )
	spf_rec = argv[2];
    else if ( strcmp( argv[1], "domain" ) == 0 )
    {
	dns_rr = SPF_dns_lookup( spfdcid, argv[2], ns_t_txt, TRUE );
    
	if ( dns_rr->herrno != NETDB_SUCCESS )
	{
	    printf( "DNS lookup for \"%s\" failed:  %d\n",
		    argv[1], dns_rr->herrno );
	    err = 1;
	    goto error;
	}
	spf_rec = dns_rr->rr[0]->txt;
    }
    else if ( strcmp( argv[1], "ip" ) == 0 )
    {
	struct in_addr ipv4;
	ipv4.s_addr = 0x04030201;
	
	dns_rr = SPF_dns_rlookup( spfdcid, ipv4, ns_t_ptr, TRUE );
    
	if ( dns_rr->herrno != NETDB_SUCCESS )
	{
	    printf( "DNS lookup for \"%s\" failed:  %d\n",
		    argv[1], dns_rr->herrno );
	    err = 1;
	    goto error;
	}
	spf_rec = dns_rr->rr[0]->txt;

	/* FIXME: do something with the rlookup */
	err = 1;
	goto error;
    }
    else if ( strcmp( argv[1], "exp" ) == 0 )
    {
	int	len;
	char	*p, *s;
	
	len = strlen( argv[2] );
	spf_rec = malloc( len * 2 + sizeof( "v=spf1 exp-text=" ) );
	
	strcpy( spf_rec, "v=spf1 exp-text=" );
	
	p = spf_rec + sizeof( "v=spf1 exp-text=" ) - 1;
	s = argv[2];

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
	
    } else {
	usage();
	err = 1;
	goto error;
    }
    
    

    printf( "SPF record in:  %s\n", spf_rec );
    err = SPF_compile( spfcid, spf_rec, &c_results );
    if ( c_results.err_msg != NULL )
	printf( "%s\n", c_results.err_msg );
    else if ( err )
	printf( "%s  (null err_msg)\n", SPF_strerror( err ) );
    else
	printf( "no errors\n" );
    
    SPF_print( c_results.spfid );

    if ( strcmp( argv[1], "exp" ) == 0 )
    {
	char	*buf = NULL;
	int	buf_len = 0;
	int	err;
	
	SPF_set_rec_dom( spfcid, "midwestcs.com" );

	SPF_set_helo_dom( spfcid, "example.com" );
	SPF_set_ipv4_str( spfcid, "192.0.2.3" );
	SPF_set_env_from( spfcid, "strong-bad@email.example.com" );

	err = SPF_find_mod_value( spfcid, c_results.spfid, spfdcid, "exp-text", &buf, &buf_len );
	if ( err )
	    printf( "%s\n", SPF_strerror( err ) );
	else
	    printf( "err=%d  buf_len = %d  buf=\"%s\"\n", err, buf_len, buf );

	free( spf_rec );
	if ( buf ) free( buf );
    }
    
  error:
    if ( spfdcid ) SPF_dns_destroy_config( spfdcid );
    if ( spfcid ) SPF_destroy_config( spfcid );
    SPF_free_c_results( &c_results );
    SPF_destroy_default_config();
    
    return err;
}
