/*
 *  spfquery - Sender Policy Framwork command line utility
 *	
 *  Author: Wayne Schlitt <wayne@midwestcs.com>
 *
 *  File:   spfquery.c
 *  Desc:   SPF command line utility
 *
 *
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
 *
 * The two-clause BSD license:
 * 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define SPF_TEST_VERSION  "2.1"


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>   /* inet_ functions / structs */
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>   /* inet_ functions / structs */
#endif

#if 0
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h> /* DNS HEADER struct */
#endif
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>    /* in_addr struct */
#endif

#ifdef HAVE_GETOPT_LONG_ONLY
#define _GNU_SOURCE
#include <getopt.h>
#else
#include "replace/getopt.h"
#endif



#include "spf.h"
#include "spf_dns.h"
#include "spf_dns_null.h"
#include "spf_dns_resolv.h"
#include "spf_dns_test.h"
#include "spf_dns_cache.h"



#define TRUE 1
#define FALSE 0


static void usage()
{
    fprintf(
	stderr,
	"Usage:\n"
	"\n"
	"spfquery [control options | data options] ...\n"
	"\n"
	"Use the -help option for more information\n"
	);
}

static void help()
{
    fprintf(
	stderr,
	"Usage:\n"
	"\n"
	"spfquery [control options | data options] ...\n"
	"\n"
	"Valid data options are:\n"
	"    -file <filename>           read spf data from a file.  Use '-'\n"
	"                               to read from stdin.\n"
	"\n"
	"    -ip <IP address>           The IP address that is sending email\n"
	"    -sender <email address>    The email address used as the\n"
	"                               envelope-from.  If no username (local\n"
	"                               part) is given, 'postmaster' will be\n"
	"                               assumed.\n"
	"    -helo <domain name>        The domain name given on the SMTP HELO\n"
	"                               command.  This is only needed if the\n"
	"                               -sender option is not given.\n"
	"    -rcpt-to <email addresses> A comma separated lists of email addresses\n"
	"                               that will have email from their secondary\n"
	"                               MXes automatically allowed.\n"
	"\n"
	"The data options are required.  The -file option conflicts with all\n"
	"the other data options.  The -helo and -rcpt-to are optional.\n"
	"\n" 
	"\n"
	"Valid control options are:\n"
	"    -debug [debug level]       debug level.\n"
	"    -local <SPF mechanisms>    Local policy for whitelisting.\n"
	"    -trusted <0|1>             Should trusted-forwarder.org be checked?\n"
	"    -guess <SPF mechanisms>    Default checks if no SPF record is found.\n"
	"    -default-explanation <str> Default explanation string to use.\n"
	"    -max-lookup <number>       Maximum number of DNS lookups to allow\n"
	"    -sanitize <0|1>            Clean up invalid characters in output?\n"
	"    -name <domain name>        The name of the system doing the SPF\n"
	"                               checking\n"
	"    -override <...>            Override SPF records for domains\n"
	"    -fallback <...>            Fallback SPF records for domains\n"
	"    -dns <dns layers>          Comma seperated list of DNS layers\n"
	"                               to use.\n"
	"\n"
	"    -keep-comments             Print comments found when reading\n"
	"                               from a file.\n"
	"    -version                   Print version of spfquery.\n"
	"    -help                      Print out these options.\n"
	"\n"
	"Examples:\n"
	"\n"
	"spfquery -ip=11.22.33.44 -sender=user@aol.com -helo=spammer.tld\n"
	"spfquery -f test_data\n"
	"echo \"127.0.0.1 myname@mydomain.com helohost.com\" | spfquery -f -\n"
	);
}


int main( int argc, char *argv[] )
{
    int c;
    int	res = 0;

    char *opt_file = NULL;

    char *opt_ip = NULL;
    char *opt_sender = NULL;
    char *opt_helo = NULL;
    char *opt_rcpt_to = NULL;

    char *opt_local = NULL;
    int   opt_trusted = 0;
    const char *opt_guess = NULL;
    const char *opt_exp = NULL;
    const char *opt_max_lookup = NULL;
    const char *opt_sanitize = NULL;
    const char *opt_name = "spfquery";
    int   opt_debug = 0;
    const char *opt_dns = "resolv,cache";
    char *opt_fallback = NULL;
    char *opt_override = NULL;

    int   opt_keep_comments = 0;
    

    char in_line[4096];
    const char *p, *p_end;
    char *p2;
    const char *prev_p, *prev_p_end;
    size_t len;
    int	 i;
    int  done_once;
    int	 major, minor, patch;

    SPF_id_t		spfid = NULL;
    SPF_config_t	spfcid = NULL;
    SPF_dns_config_t	spfdcid = NULL;
#define MAX_DNS_LAYERS 10
    SPF_dns_config_t	spfdcid_opt[MAX_DNS_LAYERS] = { NULL };
    char		*spfdcid_name[MAX_DNS_LAYERS] = { NULL };
    SPF_dns_config_t	prev_dns = NULL;
    SPF_output_t	spf_output;
    SPF_c_results_t	local_policy;
    SPF_c_results_t	exp;
    SPF_c_results_t	best_guess;
    SPF_err_t		err;
    
    FILE		*fin;

    char		*result;
    


    SPF_init_c_results( &local_policy );
    SPF_init_c_results( &exp );
    SPF_init_c_results( &best_guess );


    /*
     * check the arguments
     */

    while (1)
    {
	int option_index = 0;

	static struct option long_options[] = {
	    {"file", 1, 0, 'f'},

	    {"ip", 1, 0, 'i'},
	    {"sender", 1, 0, 's'},
	    {"helo", 1, 0, 'h'},
	    {"rcpt-to", 1, 0, 'r'},

	    {"debug", 2, 0, 'd'},
	    {"local", 1, 0, 'l'},
	    {"trusted", 1, 0, 't'},
	    {"guess", 1, 0, 'g'},
	    {"default-explanation", 1, 0, 'e'},
	    {"max-lookup", 1, 0, 'm'},
	    {"sanitize", 1, 0, 'c'},
	    {"name", 1, 0, 'n'},
	    {"override", 1, 0, 'a'},
	    {"fallback", 1, 0, 'z'},
	    {"dns", 1, 0, 'D'},

	    {"keep-comments", 0, 0, 'k'},
	    {"version", 0, 0, 'v'},
	    {"help", 0, 0, '?'},

	    {0, 0, 0, 0}
	};

	c = getopt_long_only (argc, argv, "f:i:s:h:r:lt::gemcnd::D:kz:a:v",
			      long_options, &option_index);

	if (c == -1)
	    break;

	switch (c)
	{
	case 'f':
	    opt_file = optarg;
	    break;


	case 'i':
	    opt_ip = optarg;
	    break;

	case 's':
	    opt_sender = optarg;
	    break;

	case 'h':
	    opt_helo = optarg;
	    break;

	case 'r':
	    opt_rcpt_to = optarg;
	    break;


	case 'l':
	    opt_local = optarg;
	    break;

	case 't':
	    if (optarg == NULL)
		opt_trusted = 1;
	    else
		opt_trusted = atoi( optarg );
	    break;

	case 'g':
	    opt_guess = optarg;
	    break;

	case 'e':
	    opt_exp = optarg;
	    break;

	case 'm':
	    opt_max_lookup = optarg;
	    break;

	case 'c':			/* "clean"			*/
	    opt_sanitize = optarg;
	    break;

	case 'n':			/* name of host doing SPF checking */
	    opt_name = optarg;
	    break;

	case 'a':
	    opt_override = optarg;
	    fprintf( stderr, "Unimplemented option: -override\n" );
	    break;

	case 'z':
	    opt_fallback = optarg;
	    fprintf( stderr, "Unimplemented option: -fallback\n" );
	    break;

	case 'D':			/* DNS layers to use              */
	    opt_dns = optarg;
	    break;


	case 'v':
	    fprintf( stderr, "spfquery version information:\n" );
	    fprintf( stderr, "SPF test system version: %s\n",
		     SPF_TEST_VERSION );
	    fprintf( stderr, "Compiled with SPF library version: %d.%d.%d\n",
		     SPF_LIB_VERSION_MAJOR, SPF_LIB_VERSION_MINOR,
		     SPF_LIB_VERSION_PATCH );
	    SPF_get_lib_version( &major, &minor, &patch );
	    fprintf( stderr, "Running with SPF library version: %d.%d.%d\n",
		     major, minor, patch );
	    fprintf( stderr, "\n" );
	    usage();
	    res = 255;
	    goto error;
	    break;
	    
	case 0:
	case '?':
	    help();
	    res = 255;
	    goto error;
	    break;

	case 'k':
	    opt_keep_comments = 1;
	    break;
	    
	case 'd':
	    if (optarg == NULL)
		opt_debug = 1;
	    else
		opt_debug = atoi( optarg );
	    break;

	default:
	    fprintf( stderr, "Error: getopt returned character code 0%o ??\n", c);
	}
    }

    if (optind != argc)
    {
	help();
	res = 255;
	goto error;
    }

    /*
     * set up the SPF configuration
     */

    spfcid = SPF_create_config();
    if ( spfcid == NULL )
    {
	fprintf( stderr, "SPF_create_config failed.\n" );
	res = 255;
	goto error;
    }

    SPF_set_debug( spfcid, 1 );		/* flush err msgs from init	*/
    SPF_set_debug( spfcid, opt_debug );
    if ( opt_name )
	SPF_set_rec_dom( spfcid, opt_name );
    if ( opt_sanitize )
	SPF_set_sanitize( spfcid, atoi( opt_sanitize ) );
    if ( opt_max_lookup )
	SPF_set_max_dns_mech( spfcid, atoi( opt_max_lookup ) );
    
    err = SPF_compile_local_policy( spfcid, opt_local, opt_trusted,
				    &local_policy );
    if ( err )
    {
	fprintf( stderr, "Error compiling local policy:\n%s\n",
		 local_policy.err_msg );
#if 0
	res = 255;
	goto error;
#endif
    }
    SPF_set_local_policy( spfcid, local_policy );

	
    if ( opt_exp )
    {
	err = SPF_compile_exp( spfcid, opt_exp, &exp );
	if ( err )
	{
	    fprintf( stderr, "Error compiling default explanation:\n%s\n",
		     exp.err_msg );
#if 0
	    res = 255;
	    goto error;
#endif
	}
	SPF_set_exp( spfcid, exp );
    }

    if ( opt_guess )
    {
	err = SPF_compile_local_policy( spfcid, opt_guess,
					opt_trusted, &best_guess );
	if ( err )
	{
	    fprintf( stderr, "Error compiling best guess mechanisms:\n%s",
		     best_guess.err_msg );
#if 0
	    res = 255;
	    goto error;
#endif
	}
    }


    /*
     * set up dns layers to use
     */
    p = opt_dns;
    prev_dns = NULL;
    prev_p = p;
    prev_p_end = p;
    memset( spfdcid_opt, 0, sizeof( spfdcid ) );
    for( i = 0; i < MAX_DNS_LAYERS; i++ )
    {
	p_end = p + strcspn( p, "," );
	if ( p_end - p == sizeof( "null" ) - 1
	     && strncmp( "null", p, p_end - p ) == 0 )
	{
	    len = prev_p_end - prev_p + sizeof( "pre-" );
	    if ( len > sizeof( "pre-" ) )
	    {
		spfdcid_name[i] = malloc( len + 1 );
		if ( spfdcid_name[i] )
		    snprintf( spfdcid_name[i], len, "pre-%.*s", len, prev_p );
	    }
	    else
		spfdcid_name[i] = strdup( "null" );

	    spfdcid_opt[i] = SPF_dns_create_config_null(prev_dns, opt_debug,
							spfdcid_name[i] );
	}
	else if ( p_end - p == sizeof( "resolv" ) - 1
		  && strncmp( "resolv", p, p_end - p ) == 0 )
	{
	    spfdcid_opt[i] = SPF_dns_create_config_resolv( prev_dns,
							   opt_debug );
	}
	else if ( p_end - p == sizeof( "test" ) - 1
		  && strncmp( "test", p, p_end - p ) == 0 )
	{
	    spfdcid_opt[i] = SPF_dns_create_config_test( prev_dns );
	}
	else if ( p_end - p == sizeof( "cache" ) - 1
		  && strncmp( "cache", p, p_end - p ) == 0 )
	{
	    spfdcid_opt[i] = SPF_dns_create_config_cache( prev_dns, 8,
							  opt_debug );
	    SPF_dns_set_conserve_cache( spfdcid_opt[i], FALSE );
	}

	if ( spfdcid_opt[i] == NULL )
	{
	    fprintf( stderr, "Could not create DNS layer: %.*s\n",
		     p_end - p, p );
	    res = 255;
	    goto error;
	}

	prev_dns = spfdcid_opt[i];
	prev_p = p;
	prev_p_end = p_end;
	if ( *p_end == '\0' )
	    break;
	p = p_end + 1;
    }
    
    if ( i < MAX_DNS_LAYERS-1 ) 
    {
	i++;
	len = prev_p_end - prev_p + sizeof( "pre-" );
	if ( len > 0 )
	{
	    spfdcid_name[i] = malloc( len + 1 );
	    if ( spfdcid_name[i] )
		snprintf( spfdcid_name[i], len, "pre-%.*s", len, prev_p );
	}
	    

	spfdcid_opt[i] = SPF_dns_create_config_null(prev_dns, opt_debug,
						    spfdcid_name[i] );
    }

    spfdcid = spfdcid_opt[i];
	

    /*
     * process the SPF request
     */

    if (opt_ip == NULL || (opt_sender == NULL && opt_helo == NULL) )
    {
	if (opt_file == NULL ||
	    opt_ip || opt_sender || opt_helo)
	{
	    usage();
	    res = 255;
	    goto error;
	}

	/*
	 * the requests are on STDIN
	 */

	if (strcmp( opt_file, "-" ) == 0) 
	    fin = stdin;
	else
	    fin = fopen( opt_file, "r" );

	if (!fin) 
	{
	    fprintf( stderr, "Could not open: %s\n", opt_file );
	    res = 255;
	    goto error;
	}
    } else {
	if (opt_file)
	{
	    usage();
	    res = 255;
	    goto error;
	}


	fin = NULL;
    }
    


    done_once = FALSE;
    
    while ( TRUE )
    {
	if ( fin )
	{
	    if ( fgets( in_line, sizeof( in_line ), fin ) == NULL )
		break;

	    p2 = strchr( in_line, '\n' );

	    if ( p2 )
		*p2 = '\0';

	    p2 = in_line;

	    p2 += strspn( p2, " \t\n" );
	    if ( *p2 == '\0' || *p2 == '#' )
	    {
		if ( opt_keep_comments )
		    printf( "%s\n", in_line );
		
		continue;
	    }

	    opt_ip = p2;
	    p2 += strcspn( p2, " \t\n" );
	    *p2++ = '\0';

	    p2 += strspn( p2, " \t\n" );
	    opt_sender = p2;
	    p2 += strcspn( p2, " \t\n" );
	    *p2++ = '\0';

	    p2 += strspn( p2, " \t\n" );
	    opt_helo = p2;
	    p2 += strcspn( p2, " \t\n" );
	    *p2++ = '\0';

	    p2 += strspn( p2, " \t\n" );
	    opt_rcpt_to = p2;
	    p2 += strcspn( p2, " \t\n" );
	    *p2++ = '\0';
	} else {
	    if ( done_once )
		break;
	}
	done_once = TRUE;
	
	    
	if ( SPF_set_ip_str( spfcid, opt_ip ) )
	{
	    printf( "Invalid IP address.\n" );
	    res = 255;
	    continue;
	}
	
	if ( SPF_set_helo_dom( spfcid, opt_helo ) )
	{
	    printf( "Invalid HELO domain.\n" );
	    res = 255;
	    continue;
	}
	
	if ( SPF_set_env_from( spfcid, opt_sender ) )
	{
	    printf( "Invalid envelope from address.\n" );
	    res = 255;
	    continue;
	}
	

	if ( opt_rcpt_to == NULL  || *opt_rcpt_to == '\0' )
	{
	    spf_output = SPF_result( spfcid, spfdcid );
	    result = strdup( SPF_strresult( spf_output.result ) );
	}
	else
	{
	    const char	*per_result;
	    char	*p, *next_p;
	    size_t	len;

	    result = NULL;
	    
	    /* SPF_result_2mxdoesn't support multiple rcpt-to's */
	    for( p = opt_rcpt_to; (p = strchr( p, ';' )) != NULL; )
		*p = ',';

	    for( p = next_p = opt_rcpt_to; p != NULL; p = next_p )
	    {
		next_p = strchr( p, ',' );
		if ( next_p != NULL )
		    *next_p = '\0';
	    
		spf_output = SPF_result_2mx( spfcid, spfdcid, p );
		
		per_result = SPF_strresult( spf_output.result );

		SPF_free_output( &spf_output );
		
		if ( result == NULL )
		{
		    result = strdup( per_result );

		} else {

		    len = strlen( result ) + sizeof( "," ) + strlen( per_result );
		    result = realloc( result, len );

		    strcat( result, "," );
		    strcat( result, per_result );
		}
	    }

	    spf_output = SPF_result_2mx_msg( spfcid, spfdcid );

	    per_result = SPF_strresult( spf_output.result );

	    if ( result == NULL ) {
		result = strdup( per_result );
	    }
	    else {
		len = strlen( result ) + sizeof( "," ) + strlen( per_result );
		result = realloc( result, len );

		strcat( result, "," );
		strcat( result, per_result );
	    }
	}
	
	if ( opt_debug > 0 )
	{
	    printf ( "err = %s (%d)\n",
		     SPF_strerror( spf_output.err ), spf_output.err );
	    printf ( "err_msg = %s\n", spf_output.err_msg ? spf_output.err_msg : "" );
	}

	printf( "%s\n%s\n%s\n%s\n",
		result,
		spf_output.smtp_comment ? spf_output.smtp_comment : "",
		spf_output.header_comment ? spf_output.header_comment : "",
		spf_output.received_spf ? spf_output.received_spf : "" );

	free( result );

	if ( opt_guess )
	{
	    SPF_free_output( &spf_output );

	    printf( "\nBest guess:\n" );
	    
	    spf_output = SPF_eval_id( spfcid, best_guess.spfid, spfdcid, TRUE, FALSE, NULL );
	    SPF_result_comments( spfcid, spfdcid, best_guess, &spf_output );
	    
	    if ( opt_debug > 0 )
	    {
		printf ( "result = %s (%d)\n",
			 SPF_strresult( spf_output.result ), spf_output.result );
		printf ( "err = %s (%d)\n",
			 SPF_strerror( spf_output.err ), spf_output.err );
		printf ( "err_msg = %s\n", spf_output.err_msg ? spf_output.err_msg : "" );
	    }

	    printf( "%s\n%s\n%s\n%s\n",
		    SPF_strresult( spf_output.result ),
		    spf_output.smtp_comment ? spf_output.smtp_comment : "",
		    spf_output.header_comment ? spf_output.header_comment : "",
		    spf_output.received_spf ? spf_output.received_spf : "" );
	}
	
	res = spf_output.result;

	SPF_free_output( &spf_output );

    }

  error:
    if ( spfid ) SPF_destroy_id( spfid );
    for( i = MAX_DNS_LAYERS-1; i >= 0; i-- )
    {
	if ( spfdcid_opt[i] != NULL )
	    SPF_dns_destroy_config( spfdcid_opt[i] );
	if ( spfdcid_name[i] != NULL )
	    free( spfdcid_name[i] );
    }
    if ( spfcid ) SPF_destroy_config( spfcid );
    SPF_free_c_results( &local_policy );
    SPF_free_c_results( &exp );
    SPF_free_c_results( &best_guess );
    SPF_destroy_default_config();
    
    return res;
}
