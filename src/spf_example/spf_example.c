/*
 *  spf_example - An example program for how to use libspf2
 *	
 *  Author: Wayne Schlitt <wayne@midwestcs.com>
 *
 *  File:   spfquery.c
 *  Desc:   SPF command line utility
 *
 *
 * This program is in the public domain, there is no copyright, you
 * can do anything you want with it.
 */


/*
 * The libspf2 library uses the GNU autoconf system to help make
 * the library more portable.  The config.h file should have the
 * HAVE_xxx defines that are appropriate for your system.  Either use
 * autconf to create it, or create it by hand.
 */


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
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>	/* in_addr struct */
#endif

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h> /* DNS HEADER struct */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif



/*
 * libspf2 public include files that are needed for this example
 * program
 */

#include "spf.h"


/*
 * usage() just prints out the command line options for this program
 */
static void usage()
{
	fprintf(
	stderr,
	"Usage:\n"
	"\n"
	"spf_example [options]\n"
	"\n"
	"Valid data options are:\n"
	"	-i <IP address>			The IP address that is sending email\n"
	"	-s <email address>		 The email address used as the\n"
	"							   envelope-from.  If no username (local\n"
	"							   part) is given, 'postmaster' will be\n"
	"							   assumed.\n"
	"	-r <email address>		 [optional] The email address used as\n"
	"							   the envelope-to email address, for\n"
	"							   secondary-MX checking.\n"
	"	-h <domain name>		   The domain name given on the SMTP HELO\n"
	"							   command.  This is only needed if the\n"
	"							   -sender option is not given.\n"
	"	-d [debug level]		   debug level.\n"
	);
}



/*
 * All the code is in the main routine, but most usages of libspf2
 * would have the code spread around into various subrotines.
 */

int main( int argc, char *argv[] )
{
	int c;
	int	res = 0;
	int	i;

	char *opt_ip = NULL;
	char *opt_sender = NULL;
	char *opt_helo = NULL;
	char *opt_rcpt_to = NULL;
	int   opt_debug = 0;

	/* You should not indirect on any of these structures, as their
	 * layout may change between versions of the library. Use the
	 * accessor functions instead. Definitions of the structs may not
	 * even be provided. */

	SPF_server_t		*spf_server = NULL;
	SPF_request_t		*spf_request = NULL;
	SPF_response_t		*spf_response = NULL;
	SPF_response_t		*spf_response_2mx = NULL;
	

	/*
	 * check the arguments
	 */

	while (1)
	{
	c = getopt(argc, argv, "i:s:h:r:d::" );

	if (c == -1)
		break;

	switch (c)
	{
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

	case 0:
	case '?':
		usage();
		res = 255;
		goto error;
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

	if (optind != argc
	|| opt_ip == NULL
	|| (opt_helo == NULL && opt_sender == NULL))
	{
	usage();
	res = 255;
	goto error;
	}

/*
 * Configure the SPF system.
 *
 * libspf2 is designed so that configurations can be set up once
 * and reused many times different emails delivered in a single SMTP
 * session or in different SMTP sessions.
 */

	/*
	 * set up the SPF server
	 *
	 * Configurations contain malloc'd data so must be
	 * destroyed when you are finished.
	 */

	spf_server = SPF_server_new(SPF_DNS_CACHE, 1);

	if (spf_server == NULL) {
		fprintf( stderr, "SPF_create_config failed.\n" );
		res = 255;
		goto error;
	}

	/*
	 * Create a new request.
	 *
	 * The SPF request contains all the data needed to process
	 * the SPF check. Requests are malloc'd so it must be
	 * destroyed when you are finished with it.
	 */

	spf_request = SPF_request_new(spf_server);

	/* The domain name of the receiving MTA will default to gethostname() */
	/* SPF_request_set_rec_dom( spf_request, opt_name ); */
	

/*
 * process the SPF request
 *
 * Now that the SPF system has been configured, we can process the requests.
 * There would normally be a loop around this code or it would be placed
 * in a subroutine to be called for each email.
 *
 * If a single email session sends several emails, you don't need to
 * reset the IP address or the HELO domain each time, just change the
 * envelope from.
 */

	/*
	 * record the IP address of the client (sending) MTA.
	 *
	 * There are other SPF_set_ip*() functionx if you have a structure
	 * instead of a string.
	 */

	if ( SPF_request_set_ipv4_str( spf_request, opt_ip ) ) {
		printf( "Invalid IP address.\n" );
		res = 255;
		goto error;
	}
	

	/*
	 * record the HELO domain name of the client (sending) MTA from
	 * the SMTP HELO or EHLO commands
	 *
	 * This domain name will be used if the envelope from address is
	 * null (e.g. MAIL FROM:<>).  This happens when a bounce is being
	 * sent and, in effect, it is the client MTA that is sending the
	 * message.
	 */

	if ( SPF_request_set_helo_dom( spf_request, opt_helo ) ) {
		printf( "Invalid HELO domain.\n" );
		res = 255;
		goto error;
	}

	/*
	 * record the envelope from email address from the SMTP MAIL FROM:
	 * command.
	 */

	if ( SPF_request_set_env_from( spf_request, opt_sender ) ) {
		printf( "Invalid envelope from address.\n" );
		res = 255;
		goto error;
	}

	/*
	 * now that we have all the information, see what the result of
	 * the SPF check is.
	 */

	SPF_request_query_mailfrom(spf_request, &spf_response);

	/*
	 * If the sender MAIL FROM check failed, then for each SMTP RCPT TO
	 * command, the mail might have come from a secondary MX for that
	 * domain.
	 *
	 * Note that most MTAs will also check the RCPT TO command to make sure
	 * that it is ok to accept. This SPF check won't give a free pass
	 * to all secondary MXes from all domains, just the one specified by
	 * the rcpt_to address. It is assumed that the MTA checks (at some
	 * point) that we are also a valid primary or secondary for the domain.
	 */
	if (SPF_response_result(spf_response) != SPF_RESULT_PASS) {
		SPF_request_query_rcptto(spf_request, &spf_response_2mx, opt_rcpt_to);
		/*
		 * We might now have a PASS if the mail came from a client which
		 * is a secondary MX from the domain specified in opt_rcpt_to.
		 *
		 * If not, then the RCPT TO: address must have been a domain for
		 * which the client is not a secondary MX, AND the MAIL FROM: domain
		 * doesn't doesn't return 'pass' from SPF_result()
		 */
		if (SPF_response_result(spf_response_2mx) == SPF_RESULT_PASS) {
		}
	}

	/*
	 * If the result is something like 'neutral', you probably
	 * want to accept the email anyway, just like you would
	 * when SPF_result() returns 'neutral'.
	 *
	 * It is possible that you will completely ignore the results
	 * until the SMPT DATA command.
	 */

	if ( opt_debug > 0 ) {
		printf ( "result = %s (%d)\n",
			SPF_strresult(SPF_response_result(spf_response)),
				SPF_response_result(spf_response));
		printf ( "err = %s (%d)\n",
			SPF_strerror(SPF_response_errcode(spf_response)),
				SPF_response_errcode(spf_response));
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			SPF_error_t	*err = SPF_response_message(spf_response, i);
			printf ( "%s_msg = (%d) %s\n",
				(SPF_error_errorp(err) ? "warn" : "err"),
				SPF_error_code(err),
				SPF_error_message(err));
		}
	}

#define VALID_STR(x) (x ? x : "")

	printf( "%s\n%s\n%s\n%s\n",
		SPF_strresult( SPF_response_result(spf_response) ),
		VALID_STR(SPF_response_get_smtp_comment(spf_response)),
		VALID_STR(SPF_response_get_header_comment(spf_response)),
		VALID_STR(SPF_response_get_received_spf(spf_response))
		);

	res = SPF_response_result(spf_response);


	/*
	 * The response from the SPF check contains malloced data, so
	 * make sure we free it.
	 */

	SPF_response_free(spf_response);
	if (spf_response_2mx)
		SPF_response_free(spf_response_2mx);

  error:

	/*
	 * the SPF configuration variables contain malloced data, so we
	 * have to vfree them also.
	 */

	if (spf_request)
		SPF_request_free(spf_request);
	if (spf_server)
		SPF_server_free(spf_server);
	return res;
}
