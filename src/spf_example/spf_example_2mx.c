/*
 *  spf_example_2mx - An example program for how to use the
 *                    SPF_result_2mx() functions of libspf-alt
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
 * The libspf-alt library uses the GNU autoconf system to help make
 * the library more portable.  The config.h file should have the
 * HAVE_xxx defines that are appropriate for your system.  Either use
 * autconf to create it, or create it by hand.
 */


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
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>    /* in_addr struct */
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif


/*
 * libspf-alt public include files that are needed for this example
 * program
 */

#include "spf.h"
#include "spf_dns_resolv.h"
#include "spf_dns_cache.h"



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
	"    -i <IP address>            The IP address that is sending email\n"
	"    -s <email address>         The email address used as the\n"
	"                               envelope-from.  If no username (local\n"
	"                               part) is given, 'postmaster' will be\n"
	"                               assumed.\n"
	"    -h <domain name>           The domain name given on the SMTP HELO\n"
	"                               command.  This is only needed if the\n"
	"                               -sender option is not given.\n"
	"    -r <email address>         The email address used as the\n"
	"                               envelope-to.\n"
	"    -debug [debug level]       debug level.\n"
	);
}



/*
 * All the code is in the main routine, but most usages of libspf-alt
 * would have the code spread around into various subrotines.
 */

int main( int argc, char *argv[] )
{
    int c;
    int	res = 0;

    char *opt_ip = NULL;
    char *opt_sender = NULL;
    char *opt_helo = NULL;
    char *opt_rcpt_to = NULL;
    int   opt_debug = 0;

    SPF_config_t	spfcid = NULL;
    SPF_dns_config_t	spfdcid_resolv = NULL;
    SPF_dns_config_t	spfdcid = NULL;
    SPF_output_t	spf_output;
    

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
 * libspf-alt is designed so that configurations can be set up once
 * and reused many times different emails delivered in a single SMTP
 * session or in different SMTP sessions.
 */

    /*
     * set up the SPF configuration
     *
     * The SPF configuration contains all the data needed to process
     * the SPF check.  Configurations contain malloc so it must be
     * destroyed when you are finished with it. In a multi-threaded
     * environment, you need one per thread.
     */

    spfcid = SPF_create_config();
    if ( spfcid == NULL )
    {
	fprintf( stderr, "SPF_create_config failed.\n" );
	res = 255;
	goto error;
    }


    SPF_set_debug( spfcid, opt_debug );

    /* The domain name of the receiving MTA will default to gethostname() */
    /* SPF_set_rec_dom( spfcid, opt_name ); */
    

    /*
     * set up dns layers to use
     *
     * The SPF DNS configuration layers contains data needed to do the
     * DNS lookups and to return the results.  Configurations contain
     * malloc so it must be destroyed when you are finished with
     * it. In a multi-threaded environment, you need one per thread.
     * 
     * Even a small DNS cache can reduce the CPU usage compared with
     * even a local caching name server.
     */
    spfdcid_resolv = SPF_dns_create_config_resolv( NULL, opt_debug );
    spfdcid = SPF_dns_create_config_cache( spfdcid_resolv, 8, opt_debug );
	

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

    if ( SPF_set_ip_str( spfcid, opt_ip ) )
    {
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

    if ( SPF_set_helo_dom( spfcid, opt_helo ) )
    {
	printf( "Invalid HELO domain.\n" );
	res = 255;
	goto error;
    }
	

    /*
     * record the envelope from email address from the SMTP MAIL FROM:
     * command.
     */

    if ( SPF_set_env_from( spfcid, opt_sender ) )
    {
	printf( "Invalid envelope from address.\n" );
	res = 255;
	goto error;
    }
	


    /*
     * now that we have most of the the information, see what the result of
     * the SPF check is.
     */

    /*
     * For each SMPT RCPT TO command, we need to secondary MXes forward
     * email to us.
     *
     * Note that most MTAs will also check the RCPT TO command to make sure
     * that it is ok to accept.  So, this SPF check won't give a free pass
     * to all secondary MXes from all domains, just the ones you want.
     */

    spf_output = SPF_result_2mx( spfcid, spfdcid, opt_rcpt_to );

    if ( spf_output.result != SPF_RESULT_PASS )
    {
	/*
	 * The RCPT TO: address must not have been to domain that
	 * we have secondary MXes for AND the MAIL FROM: domain
	 * doesn't doesn't return 'pass' from SPF_result()
	 *
	 * If the result is something like 'neutral', you probably
	 * want to accept the email anyway, just like you would
	 * when SPF_result() returns 'neutral'.
	 *
	 * It is possible that you will completely ignore the results
	 * until the SMPT DATA command.
	 */
    }

    SPF_free_output( &spf_output );

#if 0
    spf_output = SPF_result_2mx( spfcid, spfdcid, next_opt_rcpt_to );

    if ( spf_output.result != SPF_RESULT_PASS )
    {
	/* ... */
    }

    SPF_free_output( &spf_output );
#endif
    
    
    /*
     * When the SMPT DATA command comes along, you need to make sure
     * that the overall SPF result is acceptable.
     */

    spf_output = SPF_result_2mx_msg( spfcid, spfdcid );

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
	
    res = spf_output.result;


    /*
     * the ouput from the SPF check contains malloced data, so make sure
     * we free it.
     */

    SPF_free_output( &spf_output );

  error:

    /*
     * the SPF configuration variables contain malloced data, so we
     * have to vfree them also.
     */

    if ( spfcid ) SPF_destroy_config( spfcid );
    if ( spfdcid ) SPF_dns_destroy_config_cache( spfdcid );
    if ( spfdcid_resolv ) SPF_dns_destroy_config_resolv( spfdcid_resolv );
    SPF_destroy_default_config();
    
    return res;
}
 
