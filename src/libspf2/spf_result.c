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


#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"



char *SPF_smtp_comment( SPF_config_t spfcid, SPF_id_t spfid, SPF_dns_config_t spfdcid, SPF_output_t output )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_err_t		err;
    
    char	*buf;
    size_t	buf_len = SPF_SMTP_COMMENT_SIZE;
    
    char	*p, *p_end;


    buf = malloc( buf_len );
    if ( buf == NULL )
	return buf;
    
    err = SPF_get_exp( spfcid, spfid, spfdcid, &buf, &buf_len );
    if ( buf == NULL )
	return buf;
    
    p = buf + strlen( buf );
    p_end = buf + buf_len;


    /* FIXME  this isn't quite the same as the perl "$smtp_why" */

    if ( err == SPF_E_SUCCESS )
    {
	if ( output.reason != SPF_REASON_NONE
	     &&  output.reason != SPF_REASON_MECH )
	{
	    snprintf( p, p_end - p, " : Reason: %s",
		      SPF_strreason( output.reason ) );
	}
	    
    } else {
	if ( spfic->debug > 0 )
	    printf( "Error formatting explanation string:  %s\n",
		    SPF_strerror( err ) );

	snprintf( p, p_end - p, " : %s", SPF_strerror( err ) );
    }

    return buf;
}



char *SPF_header_comment( SPF_config_t spfcid, SPF_output_t output )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    char		*spf_source;
    
    size_t		len;

    char	ip4_buf[ INET_ADDRSTRLEN ];
    char	ip6_buf[ INET6_ADDRSTRLEN ];
    const char	*ip;

    char	*buf;
    char	*sender_dom;
    char	*p, *p_end;

    
    sender_dom = spfic->dp_from;
    if ( sender_dom == NULL ) sender_dom = spfic->helo_dom;
	

    if ( output.reason == SPF_REASON_LOCAL_POLICY )
	spf_source = strdup( "local policy" );
    else if ( output.reason == SPF_REASON_2MX )
    {
	if ( spfic->rcpt_to_dom == NULL  || spfic->rcpt_to_dom[0] == '\0' )
	    SPF_error( "RCPT TO domain is NULL" );

	spf_source = strdup( spfic->rcpt_to_dom );
    }
    else if ( sender_dom == NULL )
	spf_source = strdup( "unknown domain" );
    else
    {
	len = strlen( sender_dom ) + sizeof( "domain of " );
	spf_source = malloc( len );
	if ( spf_source )
	    snprintf( spf_source, len, "domain of %s", sender_dom );
    }


    if ( spf_source == NULL )
	return NULL;

    ip = NULL;
    if ( spfic->client_ver == AF_INET )
    {
	ip = inet_ntop( AF_INET, &spfic->ipv4,
			ip4_buf, sizeof( ip4_buf ) );
    }
    else if (spfic->client_ver == AF_INET6 )
    {
	ip = inet_ntop( AF_INET6, &spfic->ipv6,
			ip6_buf, sizeof( ip6_buf ) );
    }

    if ( ip == NULL )
	ip = "(unknown ip address)";
    

    len = strlen( spfic->rec_dom ) + strlen( spf_source ) + strlen( ip ) + 80;
    buf = malloc( len );
    if ( buf == NULL )
    {
	free( spf_source );
	return NULL;
    }
    
    p = buf;
    p_end = p + len;

    
    /* create the stock header comment */
    p += snprintf( p, p_end - p, "%s: ",  spfic->rec_dom );

    switch( output.result)
    {
    case SPF_RESULT_PASS:
	if ( output.reason == SPF_REASON_LOCALHOST )
	    snprintf( p, p_end - p, "localhost is always allowed." );
	else if ( output.reason == SPF_REASON_2MX )
	    snprintf( p, p_end - p, "message received from %s which is an MX secondary for %s.",
		      ip, spf_source );
	else
	    snprintf( p, p_end - p, "%s designates %s as permitted sender",
		      spf_source, ip );
	break;

    case SPF_RESULT_FAIL:
	snprintf( p, p_end - p, "%s does not designate %s as permitted sender",
		  spf_source, ip );
	break;

    case SPF_RESULT_SOFTFAIL:
	snprintf( p, p_end - p, "transitioning %s does not designate %s as permitted sender",
		  spf_source, ip );
	break;

    case SPF_RESULT_UNKNOWN:
	snprintf( p, p_end - p, "error in processing during lookup of %s: %s",
		      spf_source, SPF_strerror( output.err ) );
	break;
	
    case SPF_RESULT_NEUTRAL:
    case SPF_RESULT_NONE:
	snprintf( p, p_end - p, "%s is neither permitted nor denied by %s",
		  ip, spf_source );
	break;

    case SPF_RESULT_ERROR:
	snprintf( p, p_end - p, "encountered temporary error during SPF processing of %s",
		  spf_source );
	break;


    default:
	snprintf( p, p_end - p, "error: unknown SPF result %d encountered while checking %s for %s",
		  output.result, ip, spf_source );
	break;
    }
    
    if( spf_source ) free( spf_source );

    return buf;
}



char *SPF_received_spf( SPF_config_t spfcid, SPF_c_results_t c_results, SPF_output_t output )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    
    char	ip4_buf[ INET_ADDRSTRLEN ];
    char	ip6_buf[ INET6_ADDRSTRLEN ];
    const char	*ip;

    char	*buf;
    size_t	buf_len = SPF_RECEIVED_SPF_SIZE;
    
    char	*p, *p_end;


    buf = malloc( buf_len );
    if ( buf == NULL )
	return buf;
    
    p = buf;
    p_end = p + buf_len;

    
    /* create the stock Received-SPF: header */
    p += snprintf( p, p_end - p, "Received-SPF: %s (%s)",
		   SPF_strresult( output.result ),
		   output.header_comment );
    if ( p_end - p <= 0 ) return buf;

    
    
    /* add in the optional ip address keyword */
    ip = NULL;
    if ( spfic->client_ver == AF_INET )
    {
	ip = inet_ntop( AF_INET, &spfic->ipv4,
			ip4_buf, sizeof( ip4_buf ) );
    }
    else if (spfic->client_ver == AF_INET6 )
    {
	ip = inet_ntop( AF_INET6, &spfic->ipv6,
			ip6_buf, sizeof( ip6_buf ) );
    }

    if ( ip != NULL )
    {
	p += snprintf( p, p_end - p, " client-ip=%s;", ip );
	if ( p_end - p <= 0 ) return buf;
    }
    

    /* add in the optional envelope-from keyword */
    if ( spfic->env_from != NULL )
    {
	p += snprintf( p, p_end - p, " envelope-from=%s;", spfic->env_from );
	if ( p_end - p <= 0 ) return buf;
    }
    

    /* add in the optional helo domain keyword */
    if ( spfic->helo_dom != NULL )
    {
	p += snprintf( p, p_end - p, " helo=%s;", spfic->helo_dom );
	if ( p_end - p <= 0 ) return buf;
    }
    

    /* add in the optional compiler error keyword */
    if ( output.err_msg != NULL )
    {
	p += snprintf( p, p_end - p, " problem=%s;", output.err_msg );
	if ( p_end - p <= 0 ) return buf;
    }
    else if ( c_results.err_msg != NULL )
    {
	p += snprintf( p, p_end - p, " problem=%s;", c_results.err_msg );
	if ( p_end - p <= 0 ) return buf;
    }
    
    /* FIXME  should the explanation string be included in the header? */

    /* FIXME  should the header be reformated to include line breaks? */

    return buf;
}



void SPF_result_comments( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
			  SPF_c_results_t c_results, SPF_output_t *output )
{
    char		*buf;

    
    /* smtp_comment = exp= + <why string> */
    if ( c_results.spfid != NULL
	&& output->result != SPF_RESULT_PASS
	&& output->result != SPF_RESULT_NEUTRAL
	&& output->result != SPF_RESULT_UNKNOWN
	&& output->result != SPF_RESULT_NONE
	)
    {
	buf = SPF_smtp_comment( spfcid, c_results.spfid, spfdcid, *output );
	if ( buf )
	{
	    if ( output->smtp_comment ) free( output->smtp_comment );
	    output->smtp_comment = SPF_sanitize( spfcid, buf );
	}
    }

    
    /* header_comment = <list based off of SPF_result_t> */
    buf = SPF_header_comment( spfcid, *output );
    if ( buf )
    {
	if ( output->header_comment ) free( output->header_comment );
	output->header_comment = SPF_sanitize( spfcid, buf );
    }


    /* received_spf = <list based off of SPF_result_t> */
    buf = SPF_received_spf( spfcid, c_results, *output );
    if ( buf )
    {
	if ( output->received_spf ) free( output->received_spf );
	output->received_spf = SPF_sanitize( spfcid, buf );
    }

}




SPF_output_t SPF_result( SPF_config_t spfcid, SPF_dns_config_t spfdcid )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_output_t	output;
    SPF_err_t		err;
    SPF_c_results_t	c_results;



    SPF_init_output( &output );

    SPF_init_c_results( &c_results );


    /*
     * get the (compiled) SPF record
     */
    
    if ( SPF_is_loopback( spfcid ) )
    {
	output.result = SPF_RESULT_PASS;
	output.reason = SPF_REASON_LOCALHOST;
	output.err = SPF_E_SUCCESS;

    } else {

	err = SPF_get_spf( spfcid, spfdcid, NULL, &c_results );
	if ( err )
	{
	    if ( err == SPF_E_NOT_SPF )
		output.result = SPF_RESULT_NONE;
	    else
		output.result = SPF_RESULT_UNKNOWN;
	    output.reason = SPF_REASON_NONE;
	    output.err = err;
	    if ( output.err_msg ) free( output.err_msg );
	    if ( c_results.err_msg )
		output.err_msg = strdup( c_results.err_msg );
	    else
		output.err_msg = NULL;
	
	} else {
	    
	    /*
	     * find out whether this configuration passes
	     */

	    output = SPF_eval_id( spfcid, c_results.spfid, spfdcid,
				  TRUE, FALSE, NULL );
	    if ( spfic->debug > 0 )
		SPF_print( c_results.spfid );

	}
	
    }
    

    SPF_result_comments( spfcid, spfdcid, c_results, &output );

    SPF_free_c_results( &c_results );
    return output;
}


SPF_output_t SPF_result_helo( SPF_config_t spfcid, SPF_dns_config_t spfdcid )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_output_t	output;
    SPF_err_t		err;
    SPF_c_results_t	c_results;



    SPF_init_output( &output );

    SPF_init_c_results( &c_results );


    /*
     * get the (compiled) SPF record
     */
    
    if ( SPF_is_loopback( spfcid ) )
    {
	output.result = SPF_RESULT_PASS;
	output.reason = SPF_REASON_LOCALHOST;
	output.err = SPF_E_SUCCESS;
    }
    else if ( spfic->helo_dom == NULL )
    {
	output.result = SPF_RESULT_NONE;
	output.reason = SPF_REASON_NONE;
	output.err = SPF_E_NOT_CONFIG;
    }
    else
    {

	err = SPF_get_spf( spfcid, spfdcid, spfic->helo_dom, &c_results );
	if ( err )
	{
	    if ( err == SPF_E_NOT_SPF )
		output.result = SPF_RESULT_NONE;
	    else
		output.result = SPF_RESULT_UNKNOWN;
	    output.reason = SPF_REASON_NONE;
	    output.err = err;
	    if ( output.err_msg ) free( output.err_msg );
	    if ( c_results.err_msg )
		output.err_msg = strdup( c_results.err_msg );
	    else
		output.err_msg = NULL;
	
	} else {
	    
	    /*
	     * find out whether this configuration passes
	     */

	    output = SPF_eval_id( spfcid, c_results.spfid, spfdcid,
				  TRUE, TRUE, NULL );
	    if ( spfic->debug > 0 )
		SPF_print( c_results.spfid );

	}
	
    }
    

    SPF_result_comments( spfcid, spfdcid, c_results, &output );

    SPF_free_c_results( &c_results );
    return output;
}




SPF_output_t SPF_result_2mx( SPF_config_t spfcid, SPF_dns_config_t spfdcid,
			     const char *rcpt_to )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);
    SPF_output_t	output;
    SPF_err_t		err;
    SPF_c_results_t	c_results;

    size_t		buf_len;
    char		*buf;


    SPF_init_output( &output );
    SPF_free_output( &spfic->output_2mx );

    SPF_init_c_results( &c_results );


    if ( !spfic->found_non_2mx )
    {
	/* FIXME  more validation of rcpt_to needs to be done */

	spfic->rcpt_to_dom = strrchr( rcpt_to, '@' );
	if ( spfic->rcpt_to_dom != NULL )
 	    spfic->rcpt_to_dom++;	/* move past '@'		*/

	if ( spfic->rcpt_to_dom != NULL  &&  spfic->rcpt_to_dom[0] != '\0' )
	{

	    buf_len = strlen( spfic->rcpt_to_dom )
		+ sizeof( SPF_VER_STR " mx: " );
	    buf = malloc( buf_len );
    
	    snprintf( buf, buf_len, SPF_VER_STR " mx:%s", spfic->rcpt_to_dom );
	    
	    err = SPF_compile( spfcid, buf, &c_results );
	    free( buf );
	    
	    if ( err )
	    {
		if ( spfic->debug )
		    SPF_debugf( "Bad RCPT TO: %s (%s)  %s",
				rcpt_to, spfic->rcpt_to_dom, c_results.err_msg );

	    } else {
	    
		output = SPF_eval_id( spfcid, c_results.spfid, spfdcid,
				      FALSE, FALSE, NULL );
		if ( spfic->debug > 0 )
		    SPF_print( c_results.spfid );

		if ( output.result == SPF_RESULT_PASS )
		{
		    if ( spfic->debug  &&  output.reason != SPF_REASON_MECH )
			SPF_debugf( "Unexpected reason: %s",
				    SPF_strreason( output.reason ) );

		    output.reason = SPF_REASON_2MX;
		
		    SPF_result_comments( spfcid, spfdcid, c_results, &output );

		    SPF_free_c_results( &c_results );
		    spfic->output_2mx = SPF_dup_output( output );
		    spfic->found_2mx = TRUE;
		    return output;
		}
	    }

	} else {
	    if ( spfic->debug )
		SPF_debugf( "RCPT TO: missing '@' %s", rcpt_to );
	}
    }
    
    
    output = SPF_result( spfcid, spfdcid );
    
    SPF_free_c_results( &c_results );
    spfic->output_2mx = SPF_dup_output( output );
    spfic->found_non_2mx = TRUE;
    return output;
    
}


SPF_output_t SPF_result_2mx_msg( SPF_config_t spfcid, SPF_dns_config_t spfdcid )
{
    SPF_iconfig_t	*spfic = SPF_cid2spfic(spfcid);

    if ( !spfic->found_non_2mx )
    {
	if ( spfic->found_2mx )
	    return SPF_dup_output( spfic->output_2mx );

	/* this will only happen if SPF_result_2mx() wasn't called */
	SPF_free_output( &spfic->output_2mx );
	spfic->output_2mx = SPF_result( spfcid, spfdcid );
    }

    return SPF_dup_output( spfic->output_2mx );
}



const char *SPF_strresult( SPF_result_t result )
{
    switch( result )
    {
    case SPF_RESULT_PASS:		/* +				*/
	return "pass";
	break;

    case SPF_RESULT_FAIL:		/* -				*/
	return "fail";
	break;

    case SPF_RESULT_SOFTFAIL:		/* ~				*/
	return "softfail";
	break;

    case SPF_RESULT_NEUTRAL:		/* ?				*/
	return "neutral";
	break;

    case SPF_RESULT_UNKNOWN:		/* permanent error		*/
	return "unknown";
	break;

    case SPF_RESULT_ERROR:		/* temporary error		*/
	return "error";
	break;

    case SPF_RESULT_NONE:		/* no SPF record found		*/
	return "none";
	break;

    default:
	return "(invalid-result)";
	break;
    }
}


const char *SPF_strreason( SPF_reason_t reason )
{
    switch( reason )
    {
    case SPF_REASON_NONE:
	return "none";
	break;
	
    case SPF_REASON_LOCALHOST:
	return "localhost";
	break;
	
    case SPF_REASON_LOCAL_POLICY:
	return "local policy";
	break;
	
    case SPF_REASON_MECH:
	return "mechanism";
	break;
	
    case SPF_REASON_DEFAULT:
	return "default";
	break;
	
    case SPF_REASON_2MX:
	return "secondary MX";
	break;
	
    default:
	return "(invalid reason)";
	break;
	
    }
}




void SPF_init_output( SPF_output_t *output )
{
    memset( output, 0, sizeof( *output ) );
}


SPF_output_t SPF_dup_output( SPF_output_t output )
{
    SPF_output_t new_out;
    int		i;

    SPF_init_output( &new_out );

    new_out.result = output.result;
    new_out.reason = output.reason;
    new_out.err    = output.err;

    if ( output.err_msg ) new_out.err_msg = strdup( output.err_msg );

    if ( output.err_msgs )
    {
	new_out.num_errs = output.num_errs;
	new_out.err_msgs = malloc( output.num_errs * sizeof( output.err_msgs ) );
	if ( new_out.err_msgs )
	{
	    for( i = 0; i < output.num_errs; i++ )
		if ( output.err_msgs[i] )
		    new_out.err_msgs[i] = strdup( output.err_msgs[i] );
	}
    }

    if ( output.smtp_comment )
	new_out.smtp_comment = strdup( output.smtp_comment );
    if ( output.header_comment )
	new_out.header_comment = strdup( output.header_comment );
    if ( output.received_spf )
	new_out.received_spf = strdup( output.received_spf );

    return new_out;
}


void SPF_free_output( SPF_output_t *output )
{
    int		i;

    if ( output->err_msg ) free( output->err_msg );

    if ( output->err_msgs )
    {
	for( i = 0; i < output->num_errs; i++ )
	    if ( output->err_msgs[i] ) free( output->err_msgs[i] );

	free( output->err_msgs );
    }

    if ( output->smtp_comment ) free( output->smtp_comment );
    if ( output->header_comment ) free( output->header_comment );
    if ( output->received_spf ) free( output->received_spf );

    SPF_init_output( output );
}



