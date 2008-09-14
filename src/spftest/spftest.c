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




/*
 * NOTE:
 *
 * This is just a text bed that can be used while developing the
 * library.  It is not intended to make sense or to be useful.
 */

#define SPF_TEST_VERSION  "3.0"


/* we include spf_internal.h so us internal config.h */
#include "spf_sys_config.h"


#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>	   /* malloc / free */
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>	/* types (u_char .. etc..) */
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

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>	/* in_addr struct */
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>	/* in_addr struct */
#endif



#include "spf.h"
#include "spf_dns.h"
#include "spf_dns_test.h"

#include "spf_dns_internal.h"		/* we test the lookup functions		*/


#define TRUE 1
#define FALSE 0



static void usage()
{
	printf( "Usage: spftest [spf \"<spf record>\" | domain <domain name>\n" );
	printf( "                | ip <ip address> | exp \"<explanation string>\"\n" );
	printf( "                | version ]\n" );
}


int
main( int argc, char *argv[] )
{
	SPF_server_t		*spf_server = NULL;
	SPF_request_t		*spf_request = NULL;
	SPF_response_t		*spf_response = NULL;
	SPF_record_t		*spf_record = NULL;
	SPF_error_t			*spf_error = NULL;

	char				*spf_rec;
	SPF_dns_rr_t		*dns_rr = NULL;
	
	SPF_errcode_t		 err;
	int					 major, minor, patch;
	int					 i;

	spf_server = SPF_server_new(SPF_DNS_CACHE, 2);

	if ( argc <= 1 ) {
		usage();
		err = 1;
		goto error;
	}

	if ( strcmp( argv[1], "version" ) == 0 ) {
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
	
	if ( argc <= 2 ) {
		usage();
		err = 1;
		goto error;
	}
	else if ( strcmp( argv[1], "spf" ) == 0 )
		spf_rec = argv[2];
	else if ( strcmp( argv[1], "domain" ) == 0 )
	{
		dns_rr = SPF_dns_lookup( spf_server->resolver, argv[2], ns_t_txt, TRUE );
	
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
		
		dns_rr = SPF_dns_rlookup( spf_server->resolver, ipv4, ns_t_ptr, TRUE );
	
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
	else if ( strcmp( argv[1], "exp" ) == 0 ) {
		int		len;
		char		*p, *s;
		
		len = strlen( argv[2] );
		spf_rec = malloc( len * 2 + sizeof( "v=spf1 exp-text=" ) );
		
		strcpy( spf_rec, "v=spf1 exp-text=" );
		
		p = spf_rec + sizeof( "v=spf1 exp-text=" ) - 1;
		s = argv[2];

		while( *s != '\0' ) {
			if ( *s == ' ' ) {
				*p++ = '%';
				*p++ = '_';
			}
			else {
				*p++ = *s;
			}
			s++;
		}
		*p = *s;
		
	}
	else {
		usage();
		err = 1;
		goto error;
	}
	
	spf_request = SPF_request_new(spf_server);
	spf_response = SPF_response_new(spf_request);


	printf( "SPF record in:  %s\n", spf_rec );
	err = SPF_record_compile(spf_server, spf_response,
					&spf_record, spf_rec);
#if 0
	printf("Code is %d with %d messages, %d errors\n",
					err,
					SPF_response_messages(spf_response),
					SPF_response_errors(spf_response));
#endif
	if (SPF_response_messages(spf_response) > 0) {
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			spf_error = SPF_response_message(spf_response, i);
			printf( "%s: %s%s\n",
					SPF_error_errorp(spf_error) ? "Error" : "Warning",
					// SPF_error_code(spf_error),
					// SPF_strerror(SPF_error_code(spf_error)),
					((SPF_error_errorp(spf_error) && (!err))
							? "[UNRETURNED "
							: ""),
					SPF_error_message(spf_error) );
		}
		if (SPF_response_errors(spf_response) > 0) {
			if (spf_record) {
				SPF_record_free(spf_record);
				spf_record = NULL;
			}
		}
	}
	else if ( err ) {
		printf( "Error: %s (null err_msg)\n", SPF_strerror( err ) );
		if (spf_record) {
			SPF_record_free(spf_record);
			spf_record = NULL;
		}
	}
	else {
		printf( "no errors\n" );
	}

	SPF_record_print( spf_record );

#if 0
	if ( strcmp( argv[1], "exp" ) == 0 )
	{
		char		*buf = NULL;
		int		buf_len = 0;
		int		err;
		
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
#endif

  error:
	if (spf_response)
		SPF_response_free(spf_response);
	if (spf_record)
		SPF_record_free(spf_record);
	if (spf_request)
		SPF_request_free(spf_request);
	if (dns_rr)
		SPF_dns_rr_free(dns_rr);
	if (spf_server)
		SPF_server_free(spf_server);

	return err;
}
