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
 *	  Software Foundation; either version 2.1, or (at your option) any
 *	  later version,
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
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
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

#define SPF_TEST_VERSION  "3.0"

#include "libreplace/win32_config.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>   /* inet_ functions / structs */
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>   /* inet_ functions / structs */
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h> /* DNS HEADER struct */
#endif

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>	/* in_addr struct */
#endif

#ifdef HAVE_GETOPT_LONG_ONLY
#define _GNU_SOURCE
#include <getopt.h>
#else
#include "libreplace/getopt.h"
#endif

#ifdef _WIN32
#include "spf_win32.h"
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_dns_null.h"
#include "spf_dns_test.h"
#include "spf_dns_cache.h"
#ifndef _WIN32
#include "spf_dns_resolv.h"
#else
#include "spf_dns_windns.h"
#endif



#define TRUE 1
#define FALSE 0

#define FREE(x, f) do { if ((x)) (f)((x)); (x) = NULL; } while(0)
#define FREE_REQUEST(x) FREE((x), SPF_request_free)
#define FREE_RESPONSE(x) FREE((x), SPF_response_free)

#define CONTINUE_ERROR do { res = 255; continue; } while(0)
#define WARN_ERROR do { res = 255; } while(0)
#define FAIL_ERROR do { res = 255; goto error; } while(0)

#define RESIZE_RESULT(n) do { \
	if (result == NULL) { \
		result_len = 256 + n; \
		result = malloc(result_len); \
		result[0] = '\0'; \
	} \
	else if (strlen(result) + n >= result_len) { \
		result_len = result_len + (result_len >> 1) + 8 + n; \
		result = realloc(result, result_len); \
	} \
} while(0)
#define APPEND_RESULT(n) do { \
	partial_result = SPF_strresult(n); \
	RESIZE_RESULT(strlen(partial_result)); \
	strcat(result, partial_result); \
} while(0)

#define X_OR_EMPTY(x) ((x) ? (x) : "")

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

	{"keep-comments", 0, 0, 'k'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, '?'},

	{0, 0, 0, 0}
};

static void
unimplemented(const char flag)
{
	struct option	*opt;
	int				 i;

	for (i = 0; (opt = &long_options[i])->name; i++) {
		if (flag == opt->val) {
			fprintf(stderr, "Unimplemented option: -%s or -%c\n",
							opt->name, flag);
			return;
		}
	}

	fprintf(stderr, "Unimplemented option: -%c\n", flag);
}


static void
usage()
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

static void
help()
{
	fprintf(
	stderr,
	"Usage:\n"
	"\n"
	"spfquery [control options | data options] ...\n"
	"\n"
	"Valid data options are:\n"
	"	-file <filename>		   read spf data from a file.  Use '-'\n"
	"							   to read from stdin.\n"
	"\n"
	"	-ip <IP address>		   The IP address that is sending email\n"
	"	-sender <email address>	The email address used as the\n"
	"							   envelope-from.  If no username (local\n"
	"							   part) is given, 'postmaster' will be\n"
	"							   assumed.\n"
	"	-helo <domain name>		The domain name given on the SMTP HELO\n"
	"							   command.  This is only needed if the\n"
	"							   -sender option is not given.\n"
	"	-rcpt-to <email addresses> A comma separated lists of email addresses\n"
	"							   that will have email from their secondary\n"
	"							   MXes automatically allowed.\n"
	"\n"
	"The data options are required.  The -file option conflicts with all\n"
	"the other data options.  The -helo and -rcpt-to are optional.\n"
	"\n"
	"\n"
	"Valid control options are:\n"
	"	-debug [debug level]	   debug level.\n"
	"	-local <SPF mechanisms>	Local policy for whitelisting.\n"
	"	-trusted <0|1>			 Should trusted-forwarder.org be checked?\n"
	"	-guess <SPF mechanisms>	Default checks if no SPF record is found.\n"
	"	-default-explanation <str> Default explanation string to use.\n"
	"	-max-lookup <number>	   Maximum number of DNS lookups to allow\n"
	"	-sanitize <0|1>			Clean up invalid characters in output?\n"
	"	-name <domain name>		The name of the system doing the SPF\n"
	"							   checking\n"
	"	-override <...>			Override SPF records for domains\n"
	"	-fallback <...>			Fallback SPF records for domains\n"
	"\n"
	"	-keep-comments			 Print comments found when reading\n"
	"							   from a file.\n"
	"	-version				   Print version of spfquery.\n"
	"	-help					  Print out these options.\n"
	"\n"
	"Examples:\n"
	"\n"
	"spfquery -ip=11.22.33.44 -sender=user@aol.com -helo=spammer.tld\n"
	"spfquery -f test_data\n"
	"echo \"127.0.0.1 myname@mydomain.com helohost.com\" | spfquery -f -\n"
	);
}


static void
response_print_errors(const char *context,
				SPF_response_t *spf_response, SPF_errcode_t err)
{
	SPF_error_t		*spf_error;
	int				 i;

	printf("StartError\n");

	if (context != NULL)
		printf("Context: %s\n", context);
	if (err != SPF_E_SUCCESS)
		printf("ErrorCode: (%d) %s\n", err, SPF_strerror(err));

	if (spf_response != NULL) {
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			spf_error = SPF_response_message(spf_response, i);
			printf( "%s: %s%s\n",
					SPF_error_errorp(spf_error) ? "Error" : "Warning",
					// SPF_error_code(spf_error),
					// SPF_strerror(SPF_error_code(spf_error)),
					((SPF_error_errorp(spf_error) && (!err))
							? "[UNRETURNED] "
							: ""),
					SPF_error_message(spf_error) );
		}
	}
	else {
		printf("libspf2 gave a NULL spf_response\n");
	}
	printf("EndError\n");
}

static void
response_print(const char *context, SPF_response_t *spf_response)
{
	printf("--vv--\n");
	printf("Context: %s\n", context);
	if (spf_response == NULL) {
		printf("NULL RESPONSE!\n");
	}
	else {
		printf("Response result: %s\n",
					SPF_strresult(SPF_response_result(spf_response)));
		printf("Response reason: %s\n",
					SPF_strreason(SPF_response_reason(spf_response)));
		printf("Response err: %s\n",
					SPF_strerror(SPF_response_errcode(spf_response)));
		response_print_errors(NULL, spf_response,
						SPF_response_errcode(spf_response));
	}
	printf("--^^--\n");
}

typedef
struct SPF_client_options_struct {
	// void		*hook;
	char		*localpolicy;
	const char	*explanation;
	const char	*fallback;
	const char	*rec_dom;
	int 		 use_trusted;
	int			 max_lookup;
	int			 sanitize;
	int			 debug;
} SPF_client_options_t;

typedef
struct SPF_client_request_struct {
	char		*ip;
	char		*sender;
	char		*helo;
	char		*rcpt_to;
} SPF_client_request_t;

int main( int argc, char *argv[] )
{
	SPF_client_options_t	*opts;
	SPF_client_request_t	*req;

	SPF_server_t	*spf_server = NULL;
	SPF_request_t	*spf_request = NULL;
	SPF_response_t	*spf_response = NULL;
	SPF_response_t	*spf_response_2mx = NULL;
	SPF_response_t	*spf_response_fallback = NULL;
	SPF_errcode_t	 err;

	char			*opt_file = NULL;
	int  			 opt_keep_comments = 0;

	FILE			*fin;
	char			 in_line[4096];
	char			*p, *p_end;
	int 			 done_once;
	int				 major, minor, patch;

	int				 res = 0;
	int				 c;

	const char		*partial_result;
	char			*result = NULL;
	int				 result_len = 0;

	opts = (SPF_client_options_t *)malloc(sizeof(SPF_client_options_t));
	memset(opts, 0, sizeof(SPF_client_options_t));

	req = (SPF_client_request_t *)malloc(sizeof(SPF_client_request_t));
	memset(req, 0, sizeof(SPF_client_request_t));
	
	opts->rec_dom = "spfquery";

#ifdef _WIN32
	if (SPF_win32_startup() == 0) {
		fprintf( stderr, "Could not startup WinSock, wrong version." );
		FAIL_ERROR;
	}
#endif

	/*
	 * check the arguments
	 */

	for (;;) {
		int option_index;	/* Largely unused */

		c = getopt_long_only (argc, argv, "f:i:s:h:r:lt::gemcnd::kz:a:v",
				  long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'f':
				opt_file = optarg;
				break;


			case 'i':
				req->ip = optarg;
				break;

			case 's':
				req->sender = optarg;
				break;

			case 'h':
				req->helo = optarg;
				break;

			case 'r':
				req->rcpt_to = optarg;
				break;


			case 'l':
				opts->localpolicy = optarg;
				break;

			case 't':
				if (optarg == NULL)
					opts->use_trusted = 1;
				else
					opts->use_trusted = atoi(optarg);
				break;

			case 'g':
				opts->fallback = optarg;
				break;

			case 'e':
				opts->explanation = optarg;
				break;

			case 'm':
				opts->max_lookup = atoi(optarg);
				break;

			case 'c':		/* "clean"		*/
				opts->sanitize = atoi(optarg);
				break;

			case 'n':		/* name of host doing SPF checking */
				opts->rec_dom = optarg;
				break;

			case 'a':
				unimplemented('a');
				break;

			case 'z':
				unimplemented('z');
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
				FAIL_ERROR;
				break;

			case 0:
			case '?':
				help();
				FAIL_ERROR;
				break;

			case 'k':
				opt_keep_comments = 1;
				break;

			case 'd':
				if (optarg == NULL)
					opts->debug = 1;
				else
					opts->debug = atoi( optarg );
				break;

			default:
				fprintf( stderr, "Error: getopt returned character code 0%o ??\n", c);
				FAIL_ERROR;
		}
	}

	if (optind != argc) {
		help();
		FAIL_ERROR;
	}

	/*
	 * set up the SPF configuration
	 */

	spf_server = SPF_server_new(SPF_DNS_CACHE, opts->debug);

	if ( opts->rec_dom )
		SPF_server_set_rec_dom( spf_server, opts->rec_dom );
	if ( opts->sanitize )
		SPF_server_set_sanitize( spf_server, opts->sanitize );
	if ( opts->max_lookup )
		SPF_server_set_max_dns_mech(spf_server, opts->max_lookup);

	if (opts->localpolicy) {
		err = SPF_server_set_localpolicy( spf_server, opts->localpolicy, opts->use_trusted, &spf_response);
		if ( err ) {
			response_print_errors("Error setting local policy",
							spf_response, err);
			WARN_ERROR;
		}
		FREE_RESPONSE(spf_response);
	}


	if ( opts->explanation ) {
		err = SPF_server_set_explanation( spf_server, opts->explanation, &spf_response );
		if ( err ) {
			response_print_errors("Error setting default explanation",
							spf_response, err);
			WARN_ERROR;
		}
		FREE_RESPONSE(spf_response);
	}

	/*
	 * process the SPF request
	 */

	if (opt_file) {
		/*
		 * the requests are on STDIN
		 */
		if (strcmp(opt_file, "-" ) == 0)
			fin = stdin;
		else
			fin = fopen( opt_file, "r" );

		if (!fin) {
			fprintf( stderr, "Could not open: %s\n", opt_file );
			FAIL_ERROR;
		}
	}
	else {
		fin = NULL;

		if ((req->ip == NULL) ||
			(req->sender == NULL && req->helo == NULL) ) {
			usage();
			FAIL_ERROR;
		}
	}

	done_once = FALSE;

	while ( TRUE ) {
		if ( fin ) {
			if ( fgets( in_line, sizeof( in_line ), fin ) == NULL )
				break;

			in_line[strcspn(in_line, "\r\n")] = '\0';
			p = in_line;

			p += strspn( p, " \t\n" );
			{
				if ( *p == '\0' || *p == '#' ) {
					if ( opt_keep_comments )
						printf( "%s\n", in_line );
					continue;
				}
			}
			req->ip = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->sender = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->helo = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';

			p += strspn( p, " \t\n" );
			req->rcpt_to = p;
			p += strcspn( p, " \t\n" );
			*p++ = '\0';
		}
		else {
			if ( done_once )
				break;
			done_once = TRUE;
		}

		/* We have to do this here else we leak on CONTINUE_ERROR */
		FREE_REQUEST(spf_request);
		FREE_RESPONSE(spf_response);

		spf_request = SPF_request_new(spf_server);

		if (SPF_request_set_ipv4_str(spf_request, req->ip)
				&& SPF_request_set_ipv6_str(spf_request, req->ip)) {
			printf( "Invalid IP address.\n" );
			CONTINUE_ERROR;
		}

	if (req->helo) {
		if (SPF_request_set_helo_dom( spf_request, req->helo ) ) {
			printf( "Invalid HELO domain.\n" );
			CONTINUE_ERROR;
		}
	}

		if (SPF_request_set_env_from( spf_request, req->sender ) ) {
			printf( "Invalid envelope from address.\n" );
			CONTINUE_ERROR;
		}

		err = SPF_request_query_mailfrom(spf_request, &spf_response);
		if (opts->debug)
			response_print("Main query", spf_response);
		if (err) {
			response_print_errors("Failed to query MAIL-FROM",
							spf_response, err);
			CONTINUE_ERROR;
		}

		if (result != NULL)
			result[0] = '\0';
		APPEND_RESULT(SPF_response_result(spf_response));
		
		if (req->rcpt_to != NULL  && *req->rcpt_to != '\0' ) {
			p = req->rcpt_to;
			p_end = p + strcspn(p, ",;");

			/* This is some incarnation of 2mx mode. */
			while (SPF_response_result(spf_response)!=SPF_RESULT_PASS) {
				if (*p_end)
					*p_end = '\0';
				else
					p_end = NULL;	/* Note this is last rcpt */

				err = SPF_request_query_rcptto(spf_request,
								&spf_response_2mx, p);
				if (opts->debug)
					response_print("2mx query", spf_response_2mx);
				if (err) {
					response_print_errors("Failed to query RCPT-TO",
									spf_response, err);
					CONTINUE_ERROR;
				}

				/* append the result */
				APPEND_RESULT(SPF_response_result(spf_response_2mx));

				spf_response = SPF_response_combine(spf_response,
								spf_response_2mx);

				if (!p_end)
					break;
				p = p_end + 1;
			}
		}

		/* We now have an option to call SPF_request_query_fallback */
		if (opts->fallback) {
			err = SPF_request_query_fallback(spf_request,
							&spf_response_fallback, opts->fallback);
			if (opts->debug)
				response_print("fallback query", spf_response_fallback);
			if (err) {
				response_print_errors("Failed to query best-guess",
								spf_response_fallback, err);
				CONTINUE_ERROR;
			}

			/* append the result */
			APPEND_RESULT(SPF_response_result(spf_response_fallback));

			spf_response = SPF_response_combine(spf_response,
							spf_response_fallback);
		}

		printf( "%s\n%s\n%s\n%s\n",
			result,
			X_OR_EMPTY(SPF_response_get_smtp_comment(spf_response)),
			X_OR_EMPTY(SPF_response_get_header_comment(spf_response)),
			X_OR_EMPTY(SPF_response_get_received_spf(spf_response))
			);

		res = SPF_response_result(spf_response);

		fflush(stdout);
	}

  error:
	FREE(result, free);
	FREE_RESPONSE(spf_response);
	FREE_REQUEST(spf_request);
	FREE(spf_server, SPF_server_free);

#ifdef _WIN32
	SPF_win32_cleanup();
#endif

	return res;
}
