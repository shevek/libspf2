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
 *
 *
 *
 * This program is really a badly smashed together copy of spfquery.c and
 * the public domain "helloserver" example daemon.
 *
 * The original helloserver code contained the following copyright notice:
 *
 * HELLOSERVER.C - a 'Hello World' TCP/IP based server daemon
 *
 * Implements a skeleton of a single process iterative server
 * daemon.
 *
 * Wherever possible the code adheres to POSIX.
 *
 * David Gillies <daggillies@yahoo.com> Sep 2003
 *
 * Placed in the public domain. Unrestricted use or modification
 * of this code is permitted without attribution to the author.
 */


#ifdef __GNUC__
#define _GNU_SOURCE /* for strsignal() */
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>       /* malloc / free */
# include <stddef.h>
# include <stdarg.h>
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

#ifdef HAVE_GETOPT_LONG_ONLY
#define _GNU_SOURCE
#include <getopt.h>
#else
#include "replace/getopt.h"
#endif

#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <ctype.h>
#include <sys/wait.h>


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
	"spfd [control options | data options] ...\n"
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
	"spfd [options] ...\n"
	"\n"
	"Valid options are:\n"
	"Internet domain socket options (TCP):\n"
	"    -localhost                 Only allow the localhost to\n"
	"                               connect to the daemon. (default)\n"
	"    -anyhost                   Allow any host to connect.\n"
	"    -port <port number>        TCP port number to bind to.  The\n"
	"                               default is 51969.\n"
	"\n"
	"Unix domain socket options:\n"
	"    -file <socket path>        Unix domain socket path to use.\n"
	"\n"
	"The Internet and Unix domain options are mutlually exlusive.\n"
	"\n"
	"    -debug [debug level]       Debug level.\n"
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
	"    -version                   Print version of spfquery.\n"
	"    -help                      Print out these options.\n"
	);
}


/*************************************************************************/

/* global variables and constants */

volatile sig_atomic_t   gGracefulShutdown=0;
volatile sig_atomic_t   gCaughtHupSignal=0;

int                     gLockFileDesc=-1;
int                     gMasterSocket=-1;

/* the 'well-known' port on which our server will be listening */

const int               gSpfdPort=51969;

/* the path to our lock file */

const char *const       gLockFilePath="/var/run/spfd.pid";

/*************************************************************************/

#define BUFLEN 1024


/* prototypes */

int BecomeDaemonProcess(const char *const lockFileName,
                        const char *const logPrefix,
                        const int logLevel,
                        int *const lockFileDesc );
int ConfigureSignalHandlers(void);
int BindPassiveSocket(const unsigned long interfaceAddress,
                      const int portNum,
                      int *const boundSocket);
int BindPassiveUnixSocket(char *file, int *const boundSocket);
int AcceptConnections(const int master,
		     SPF_config_t spfcid, SPF_dns_config_t spfdcid,
		     SPF_c_results_t local_policy,
		     SPF_c_results_t best_guess );
int HandleConnection(const int slave,
		     SPF_config_t spfcid, SPF_dns_config_t spfdcid,
		     SPF_c_results_t local_policy,
		     SPF_c_results_t best_guess );
int WriteToSocket(const int sock,const char *const buffer,
                  const size_t buflen);
int PrintfToSocket(const int sock,const int dbg,const char *const buffer,
		   const size_t buflen, const char *const format, ... );
int ReadLine(const int sock,char *const buffer,const size_t buflen,
             size_t *const bytesRead);
void FatalSigHandler(int sig);
void TermHandler(int sig);
void HupHandler(int sig);
void Usr1Handler(int sig);
void TidyUp(void);
void wait_child(int sig);


/*************************************************************************/

/* an idea from 'Advanced Programming in the Unix Environment'
   Stevens 1993 - see BecomeDaemonProcess() */

#define OPEN_MAX_GUESS 256

/*************************************************************************/

int main( int argc, char *argv[] )
{
    int                  result;
   
    /*************************************************************/
    /* perhaps at this stage you would read a configuration file */
    /*************************************************************/

    int c;
    int	res = 0;

    char *opt_file = NULL;

    int	 opt_localhost = TRUE;
    short opt_port = htons(gSpfdPort);
    
    const char *opt_local = NULL;
    int   opt_trusted = 0;
    const char *opt_guess = NULL;
    const char *opt_exp = NULL;
    const char *opt_max_lookup = NULL;
    const char *opt_sanitize = NULL;
    const char *opt_name = NULL;
    int   opt_cache = 12;
    int   opt_debug = 0;
    const char *opt_dns = "resolv,cache";
    const char *opt_fallback = NULL;
    const char *opt_override = NULL;

    const char *p, *p_end;
    const char *prev_p, *prev_p_end;
    size_t len;
    int	 i;
    int	 major, minor, patch;

    unsigned long interface;


    SPF_config_t	spfcid = NULL;
    SPF_dns_config_t	spfdcid = NULL;
#define MAX_DNS_LAYERS 10
    SPF_dns_config_t	spfdcid_opt[MAX_DNS_LAYERS] = { NULL };
    char		*spfdcid_name[MAX_DNS_LAYERS] = { NULL };
    SPF_dns_config_t	prev_dns = NULL;
    SPF_c_results_t	local_policy;
    SPF_c_results_t	exp;
    SPF_c_results_t	best_guess;
    SPF_err_t		err;
    

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
	    {"localhost", 0, 0, 'h'},
	    {"anyhost", 0, 0, 'H'},
	    {"port", 1, 0, 'p'},
	    {"file", 1, 0, 'f'},

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
	    {"cache", 1, 0, 'C'},

	    {"version", 0, 0, 'v'},
	    {"help", 0, 0, '?'},

	    {0, 0, 0, 0}
	};

	c = getopt_long_only (argc, argv, "hHp:f:d::ltgemcna:z:C:D:v",
			      long_options, &option_index);

	if (c == -1)
	    break;

	switch (c)
	{
	case 'h':			/* allow connections from localhost */
	    opt_localhost = TRUE;
	    break;

	case 'H':			/* allow connections from any host */
	    opt_localhost = FALSE;
	    break;

	case 'p':			/* port to use			*/
	    opt_port = htons(atoi( optarg ));
	    break;


	case 'f':
	    opt_file = optarg;
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

	case 'C':			/* cache size in bits		*/
	    opt_cache = atoi( optarg );
	    break;

	case 'D':			/* DNS layers to use              */
	    opt_dns = optarg;
	    break;


	case 'v':
	    fprintf( stderr, "spfd version information:\n" );
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
#if 1
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
#if 1
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
#if 1
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
	    if ( len > 0 )
	    {
		spfdcid_name[i] = malloc( len + 1 );
		if ( spfdcid_name[i] )
		    snprintf( spfdcid_name[i], len, "pre-%.*s", len, prev_p );
	    }

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
	


    /* the first task is to put ourself into the background (i.e
       become a daemon. */

    if ( opt_debug == 0 )
    {
	if((result=BecomeDaemonProcess(gLockFilePath,"spfd",
				       LOG_DEBUG,&gLockFileDesc))<0)
	{
	    perror("Failed to become daemon process");
	    exit(result);
	}
    } else {
	umask(0); /* set this to whatever is appropriate for you */

	fprintf( stderr, "SPF daemon started in debug mode\n" );
    }
    


    /* set up signal processing */

    if((result=ConfigureSignalHandlers())<0)
    {
	syslog(LOG_MAIL|LOG_INFO,"ConfigureSignalHandlers failed, errno=%d",errno);
	unlink(gLockFilePath);
	exit(result);
    }

    /* now we must create a socket and bind it to a port */

    if(opt_localhost)
	interface=htonl(INADDR_LOOPBACK);
    else
	interface=htonl(INADDR_ANY);

    if(opt_file)
    {
	if((result=BindPassiveUnixSocket(opt_file,&gMasterSocket))<0)
	{
	    syslog(LOG_MAIL|LOG_INFO,"BindPassiveUnixSocket failed, errno=%d",errno);
	    unlink(gLockFilePath);
	    exit(result);
	}
    } else {
	if((result=BindPassiveSocket(interface,opt_port,&gMasterSocket))<0)
	{
	    syslog(LOG_MAIL|LOG_INFO,"BindPassiveSocket failed, errno=%d",errno);
	    unlink(gLockFilePath);
	    exit(result);
	}
    }
    if ( opt_debug > 0 )
	signal(SIGCHLD, wait_child);


    /* now enter an infinite loop handling connections */

    do
    {
	if(AcceptConnections(gMasterSocket,spfcid,spfdcid,local_policy,best_guess)<0)
	{
	    syslog(LOG_MAIL|LOG_INFO,"AcceptConnections failed, errno=%d",errno);
	    unlink(gLockFilePath);
	    exit(result);
	}
      
	/* the next conditional will be true if we caught signal SIGUSR1 */

	if((gGracefulShutdown==1)&&(gCaughtHupSignal==0))
	    break;

	/* if we caught SIGHUP, then start handling connections again */

	gGracefulShutdown=gCaughtHupSignal=0;
    }while(1);

    TidyUp(); /* close the socket and kill the lock file */

    res = 0;
    
  error:
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

/**************************************************************************/
/***************************************************************************

   BecomeDaemonProcess

   Fork the process into the background, make a lock file, and open the
   system log.

   Inputs:

   lockFileName I               the path to the lock file

   logPrefix    I               the string that will appear at the
                                start of all log messages

   logLevel     I               the logging level for this process

   lockFileDesc O               the file descriptor of the lock file

   thisPID      O               the PID of this process after fork()
                                has placed it in the background
   Returns:

   status code indicating success - 0 = success
   
***************************************************************************/
/**************************************************************************/

int BecomeDaemonProcess(const char *const lockFileName,
                        const char *const logPrefix,
                        const int logLevel,
                        int *const lockFileDesc )
{
    int                  curPID,stdioFD,lockResult,killResult,lockFD,i,
	numFiles;
    char                 pidBuf[17],*lfs,pidStr[7];
    FILE                 *lfp;
    unsigned long        lockPID;
    struct flock         exclusiveLock;

    /* set our current working directory to root to avoid tying up
       any directories. In a real server, we might later change to
       another directory and call chroot() for security purposes
       (especially if we are writing something that serves files */

    chdir("/");
   
    /* try to grab the lock file */

    lockFD=open(lockFileName,O_RDWR|O_CREAT|O_EXCL,0644);
   
    if(lockFD==-1)
    {
	/* Perhaps the lock file already exists. Try to open it */

	lfp=fopen(lockFileName,"r");

	if(lfp==0) /* Game over. Bail out */
	{
	    perror("Can't get lockfile");
	    return -1;
	}

	/* We opened the lockfile. Our lockfiles store the daemon PID in them.
	   Find out what that PID is */

	lfs=fgets(pidBuf,sizeof(pidBuf)-1,lfp);

	if(lfs!=0)
	{
	    if(pidBuf[strlen(pidBuf)-1]=='\n') /* strip linefeed */
		pidBuf[strlen(pidBuf)-1]=0;
         
	    lockPID=strtoul(pidBuf,(char**)0,10);
         
	    /* see if that process is running. Signal 0 in kill(2) doesn't
	       send a signal, but still performs error checking */
         
	    killResult=kill(lockPID,0);
         
	    if(killResult==0)
            {
		printf("\n\nERROR\n\nA lock file %s has been detected. It appears it is owned\nby the (active) process with PID %ld.\n\n",lockFileName,lockPID);
            }
	    else
            {
		if(errno==ESRCH) /* non-existent process */
		{
		    printf("\n\nERROR\n\nA lock file %s has been detected. It appears it is owned\nby the process with PID %ld, which is now defunct. Delete the lock file\nand try again.\n\n",lockFileName,lockPID);
		}
		else
		{
		    perror("Could not acquire exclusive lock on lock file");
		}
            }
	}
	else
	    perror("Could not read lock file");

	fclose(lfp);
      
	return -1;
    }

    /* we have got this far so we have acquired access to the lock file.
       Set a lock on it */

    exclusiveLock.l_type=F_WRLCK; /* exclusive write lock */
    exclusiveLock.l_whence=SEEK_SET; /* use start and len */
    exclusiveLock.l_len=exclusiveLock.l_start=0; /* whole file */
    exclusiveLock.l_pid=0; /* don't care about this */
    lockResult=fcntl(lockFD,F_SETLK,&exclusiveLock);
   
    if(lockResult<0) /* can't get a lock */
    {
	close(lockFD);
	perror("Can't get lockfile");
	return -1;
    }

    /* now we move ourselves into the background and become a daemon.
       Remember that fork() inherits open file descriptors among others so
       our lock file is still valid */

    curPID=fork();

    switch(curPID)
    {
    case 0: /* we are the child process */
        break;

    case -1: /* error - bail out (fork failing is very bad) */
        fprintf(stderr,"Error: initial fork failed: %s\n",
                strerror(errno));
        return -1;
        break;

    default: /* we are the parent, so exit */
        exit(0);
        break;
    }

    /* make the process a session and process group leader. This simplifies
       job control if we are spawning child servers, and starts work on
       detaching us from a controlling TTY */

    if(setsid()<0)
	return -1;
   
    /* ignore SIGHUP as this signal is sent when session leader terminates */

    signal(SIGHUP,SIG_IGN);

    /* fork again to let session group leader exit. Now we can't
       have a controlling TTY. */

    curPID=fork();

    switch(curPID) /* return codes as before */
    {
    case 0:
        break;

    case -1:
        return -1;
        break;

    default:
        exit(0);
        break;
    }

    /* log PID to lock file */

    /* truncate just in case file already existed */
   
    if(ftruncate(lockFD,0)<0)
	return -1;

    /* store our PID. Then we can kill the daemon with
       kill `cat <lockfile>` where <lockfile> is the path to our
       lockfile */
   
    snprintf(pidStr,sizeof(pidStr),"%d\n",(int)getpid());
   
    write(lockFD,pidStr,strlen(pidStr));

    *lockFileDesc=lockFD; /* return lock file descriptor to caller */
   
    /* close open file descriptors */

    numFiles=sysconf(_SC_OPEN_MAX); /* how many file descriptors? */
   
    if(numFiles<0) /* sysconf has returned an indeterminate value */
	numFiles=OPEN_MAX_GUESS; /* from Stevens '93 */
      
    for(i=numFiles-1;i>=0;--i) /* close all open files except lock */
    {
	if(i!=lockFD) /* don't close the lock file! */
	    close(i);
    }
   
    /* stdin/out/err to /dev/null */

    umask(0); /* set this to whatever is appropriate for you */

    stdioFD=open("/dev/null",O_RDWR); /* fd 0 = stdin */
    dup(stdioFD); /* fd 1 = stdout */
    dup(stdioFD); /* fd 2 = stderr */

    /* open the system log - here we are using the LOCAL0 facility */

    openlog(logPrefix,LOG_PID|LOG_CONS|LOG_NDELAY|LOG_NOWAIT,LOG_MAIL);

    SPF_error_handler = SPF_error_syslog;
    SPF_warning_handler = SPF_warning_syslog;
    SPF_info_handler = SPF_info_syslog;
    SPF_debug_handler = SPF_debug_syslog;
    

    (void)setlogmask(LOG_UPTO(logLevel)); /* set logging level */

    /* put server into its own process group. If this process now spawns
       child processes, a signal sent to the parent will be propagated
       to the children */

    setpgid(0,0);

    return 0;
}

/**************************************************************************/
/***************************************************************************

   ConfigureSignalHandlers

   Set up the behaviour of the various signal handlers for this process.
   Signals are divided into three groups: those we can ignore; those that
   cause a fatal error but in which we are not particularly interested and
   those that are used to control the server daemon. We don't bother with
   the new real-time signals under Linux since these are blocked by default
   anyway.

   Returns: none

***************************************************************************/
/**************************************************************************/

int ConfigureSignalHandlers(void)
{
    struct sigaction     sighupSA,sigusr1SA,sigtermSA;

    /* ignore several signals because they do not concern us. In a
       production server, SIGPIPE would have to be handled as this
       is raised when attempting to write to a socket that has
       been closed or has gone away (for example if the client has
       crashed). SIGURG is used to handle out-of-band data. SIGIO
       is used to handle asynchronous I/O. SIGCHLD is very important
       if the server has forked any child processes. */

#ifdef SIGUSR2
    signal(SIGUSR2,SIG_IGN);   
#endif
#ifdef SIGPIPE
    signal(SIGPIPE,SIG_IGN);
#endif
#ifdef SIGALRM
    signal(SIGALRM,SIG_IGN);
#endif
#ifdef SIGTSTP
    signal(SIGTSTP,SIG_IGN);
#endif
#ifdef SIGTTIN
    signal(SIGTTIN,SIG_IGN);
#endif
#ifdef SIGTTOU
    signal(SIGTTOU,SIG_IGN);
#endif
#ifdef SIGURG
    signal(SIGURG,SIG_IGN);
#endif
#ifdef SIGXCPU
    signal(SIGXCPU,SIG_IGN);
#endif
#ifdef SIGXFSZ
    signal(SIGXFSZ,SIG_IGN);
#endif
#ifdef SIGVTALRM
    signal(SIGVTALRM,SIG_IGN);
#endif
#ifdef SIGPROF
    signal(SIGPROF,SIG_IGN);
#endif
#ifdef SIGIO
    signal(SIGIO,SIG_IGN);
#endif
#ifdef SIGCHLD
    signal(SIGCHLD,SIG_IGN);
#endif

    /* these signals mainly indicate fault conditions and should be logged.
       Note we catch SIGCONT, which is used for a type of job control that
       is usually inapplicable to a daemon process. We don't do anyting to
       SIGSTOP since this signal can't be caught or ignored. SIGEMT is not
       supported under Linux as of kernel v2.4 */

#ifdef SIGQUIT
    signal(SIGQUIT,FatalSigHandler);
#endif
#ifdef SIGILL
    signal(SIGILL,FatalSigHandler);
#endif
#ifdef SIGTRAP
    signal(SIGTRAP,FatalSigHandler);
#endif
#ifdef SIGABRT
    signal(SIGABRT,FatalSigHandler);
#endif
#ifdef SIGIOT
    signal(SIGIOT,FatalSigHandler);
#endif
#ifdef SIGBUS
    signal(SIGBUS,FatalSigHandler);
#endif
#ifdef SIGEMT
    signal(SIGEMT,FatalSigHandler);
#endif
#ifdef SIGFPE
    signal(SIGFPE,FatalSigHandler);
#endif
#ifdef SIGSEGV
    signal(SIGSEGV,FatalSigHandler);
#endif
#ifdef SIGSTKFLT
    signal(SIGSTKFLT,FatalSigHandler);
#endif
#ifdef SIGCONT
    signal(SIGCONT,FatalSigHandler);
#endif
#ifdef SIGPWR
    signal(SIGPWR,FatalSigHandler);
#endif
#ifdef SIGSYS
    signal(SIGSYS,FatalSigHandler);
#endif
   
    /* these handlers are important for control of the daemon process */

    /* TERM  - shut down immediately */
   
    sigtermSA.sa_handler=TermHandler;
    sigemptyset(&sigtermSA.sa_mask);
    sigtermSA.sa_flags=0;
    sigaction(SIGTERM,&sigtermSA,NULL);
      
    /* USR1 - finish serving the current connection and then close down
       (graceful shutdown) */
   
    sigusr1SA.sa_handler=Usr1Handler;
    sigemptyset(&sigusr1SA.sa_mask);
    sigusr1SA.sa_flags=0;
    sigaction(SIGUSR1,&sigusr1SA,NULL);
   
    /* HUP - finish serving the current connection and then restart
       connection handling. This could be used to force a re-read of
       a configuration file for example */
   
    sighupSA.sa_handler=HupHandler;
    sigemptyset(&sighupSA.sa_mask);
    sighupSA.sa_flags=0;
    sigaction(SIGHUP,&sighupSA,NULL);
   
    return 0;
}

/**************************************************************************/
/***************************************************************************

   BindPassiveSocket

   Create a socket, bind it to a port and then place it in passive
   (listen) mode to handle client connections.

   Inputs:

   FIXME  this doc is wrong
   interface    I               the IP address that should be bound
                                to the socket. This is important for
                                multihomed hosts, which may want to 
                                restrict themselves to listening on a
                                given interface. If this is not the case,
                                use the special constant INADDR_ANY to
                                listen on all interfaces.

   Returns:

   status code indicating success - 0 = success
   
***************************************************************************/
/**************************************************************************/

int BindPassiveSocket(const unsigned long interface,
                      const int portNum,
                      int *const boundSocket)
{
    struct sockaddr_in           sin;
    struct protoent              *proto;
    int                          newsock,optval;
    size_t                       optlen;
   
    /* get the number of the TCP protocol */
    if((proto=getprotobyname("tcp"))==NULL)
	return -1;

    /* clear the socket address structure */
   
    memset(&sin.sin_zero,0,8);

    /* set up the fields. Note htonX macros are important for
       portability */

    sin.sin_port=portNum;
    sin.sin_family=AF_INET; /* Usage: AF_XXX here, PF_XXX in socket() */
    sin.sin_addr.s_addr=interface;

    if((newsock=socket(PF_INET,SOCK_STREAM,proto->p_proto))<0)
	return -1;
   
    /* The SO_REUSEADDR socket option allows the kernel to re-bind
       local addresses without delay (for our purposes, it allows re-binding
       while the previous socket is in TIME_WAIT status, which lasts for
       two times the Maximum Segment Lifetime - anything from
       30 seconds to two minutes). It should be used with care as in
       general you don't want two processes sharing the same port. There are
       also dangers if a client tries to re-connect to the same port a
       previous server used within the 2*MSL window that TIME_WAIT provides.
       It's handy for us so the server can be restarted without having to
       wait for termination of the TIME_WAIT period. */

    optval=1;
    optlen=sizeof(int);
    setsockopt(newsock,SOL_SOCKET,SO_REUSEADDR,&optval,optlen);
   
    /* bind to the requested port */
   
    if(bind(newsock,(struct sockaddr*)&sin,sizeof(struct sockaddr_in))<0)
	return -1;
        
    /* put the socket into passive mode so it is lisetning for connections */
        
    if(listen(newsock,SOMAXCONN)<0)
	return -1;
   
    *boundSocket=newsock;
   
    return 0;
}

/**************************************************************************/
/***************************************************************************

   BindPassiveUnixSocket

   Create a socket, bind it to a port and then place it in passive
   (listen) mode to handle client connections.

   Inputs:

   FIXME  this doc is wrong
   interface    I               the IP address that should be bound
                                to the socket. This is important for
                                multihomed hosts, which may want to 
                                restrict themselves to listening on a
                                given interface. If this is not the case,
                                use the special constant INADDR_ANY to
                                listen on all interfaces.

   Returns:

   status code indicating success - 0 = success
   
***************************************************************************/
/**************************************************************************/

int BindPassiveUnixSocket(char *file, int *const boundSocket)
{
    struct sockaddr_un           s_un;
    int                          newsock,optval;
    size_t                       optlen;
   
    /* clear the socket address structure */
   
    memset(&s_un,0,sizeof(s_un));

    /* set up the fields. Note htonX macros are important for
       portability */

    s_un.sun_family=AF_UNIX; /* Usage: AF_XXX here, PF_XXX in socket() */
/*    strcpy(s_un.sun_path+1, file); */
    strcpy(s_un.sun_path, file);

    if((newsock=socket(PF_UNIX,SOCK_STREAM,0))<0)
	return -1;
   
    /* The SO_REUSEADDR socket option allows the kernel to re-bind
       local addresses without delay (for our purposes, it allows re-binding
       while the previous socket is in TIME_WAIT status, which lasts for
       two times the Maximum Segment Lifetime - anything from
       30 seconds to two minutes). It should be used with care as in
       general you don't want two processes sharing the same port. There are
       also dangers if a client tries to re-connect to the same port a
       previous server used within the 2*MSL window that TIME_WAIT provides.
       It's handy for us so the server can be restarted without having to
       wait for termination of the TIME_WAIT period. */

    optval=1;
    optlen=sizeof(int);
    setsockopt(newsock,SOL_SOCKET,SO_REUSEADDR,&optval,optlen);
   
    /* bind to the requested port */
   
    if(bind(newsock,(struct sockaddr*)&s_un,sizeof(struct sockaddr_in))<0)
	return -1;
        
    /* put the socket into passive mode so it is lisetning for connections */
        
    if(listen(newsock,SOMAXCONN)<0)
	return -1;
   
    *boundSocket=newsock;
   
    return 0;
}

/* Note on restartable system calls:

several of the following functions check the return value from 'slow'
system calls (i.e. calls that can block indefinitely in the kernel)
and continue operation if the return value is EINTR. This error is
given if a system call is interrupted by a signal. However, many systems
can automatically restart system calls. Automatic restart is enabled by
setting the SA_RESTART flag in the sa_flags field of the struct sigaction.
We do not do this as we want the loop on accept() in AcceptConnections() to
look at the gGracefulShutdown flag which is set on recept of SIGHUP and
SIGUSR1 and is used to control the server.

You should still check for return code EINTR even if you have set SA_RESTART
to be on the safe side. Note that this simple behaviour WILL NOT WORK for
the connect() system call on many systems (although Linux appears to be an
exception). On such systems, you will need to call poll() or select() if
connect() is interrupted.

*/

/**************************************************************************/
/***************************************************************************

   AcceptConnections

   Repeatedly handle connections, blocking on accept() and then
   handing off the request to the HandleConnection function.
   
   Inputs:

   master       I               the master socket that has been
                                bound to a port and is listening
                                for connection attempts

   Returns:

   status code indicating success - 0 = success
   
***************************************************************************/
/**************************************************************************/

int AcceptConnections(const int master,
		      SPF_config_t spfcid, SPF_dns_config_t spfdcid,
		      SPF_c_results_t local_policy,
		      SPF_c_results_t best_guess )
{
    int                  proceed=1,slave,retval=0,childpid;
    struct sockaddr_in   client;
    socklen_t            clilen;
    int			 dbg=SPF_get_debug( spfcid );

    while((proceed==1)&&(gGracefulShutdown==0))
    {
	/* block in accept() waiting for a request */

	clilen=sizeof(client);

	slave=accept(master,(struct sockaddr *)&client,&clilen);

	if(slave<0) /* accept() failed */
	{
	    if(errno==EINTR)
		continue;

	    syslog(LOG_MAIL|LOG_INFO,"accept() failed: %m\n");
	    proceed=0;
	    retval=-1;
	}
	else
	{
	    if ( dbg > 0 )
	    {
		retval=HandleConnection(slave,spfcid,spfdcid,local_policy,best_guess); /* process connection */
		if(retval)
		    proceed=0;
	    } else {
		
		if ( (childpid = fork()) < 0)
		{
		    proceed=0;
		}
		else if (childpid == 0)
		{
		    close(master);		/* close original socket */

		    retval=HandleConnection(slave,spfcid,spfdcid,local_policy,best_guess); /* process connection */
		    if(retval)
			proceed=0;
		
		    exit( 0 );
		}
	    }

	}

	close(slave);
    }

    return retval;
}

/**************************************************************************/
/***************************************************************************

   GetOption

 FIXME add doc block

   
***************************************************************************/
/**************************************************************************/

static int GetOption(const int slave, char **str, char *readbuf,
	      const size_t buflen )
{
    size_t               bytesRead;
    int                  retval;

    char *p;

    retval=ReadLine(slave,readbuf,buflen,&bytesRead);
    if ( bytesRead == 0 )
	return -1;

/*    WriteToSocket(slave,readbuf,bytesRead); */
    
    /* truncate string at the cr/newline (if any) */
    p = readbuf + strcspn( readbuf, "\r\n" );
    *p = '\0';

    /* remove any trailing whitespace */
    p--;
    while( p != readbuf && isspace( (unsigned char)*p ) )
	*p = '\0';
	    
    /* skip over any leading whitespace */
    p = readbuf + strspn( readbuf, " \t" );


    /* special commands */
    if ( *p == '\0' ||  *p == '#' )
	return 0;

    if ( strcasecmp( p, "quit" ) == 0 )
	return -1;


    *str = p;

    return 1;
}

/**************************************************************************/
/***************************************************************************

   HandleConnection

   Service connections from the client. In practice, this function
   would probably be used as a 'switchboard' to dispatch control to
   helper functions based on the exact content of the client request.
   Here, we simply read a CRLF-terminated line (the server is intended
   to be exercised for demo purposes via a telnet client) and echo it
   back to the client.
   
   Inputs:

   sock         I               the socket descriptor for this
                                particular connection event

   Returns:

   status code indicating success - 0 = success
   
***************************************************************************/
/**************************************************************************/

int HandleConnection(const int slave,
		     SPF_config_t spfcid, SPF_dns_config_t spfdcid,
		     SPF_c_results_t local_policy,
		     SPF_c_results_t best_guess )
{

    char                 readbuf[BUFLEN + 1];
    char                 writebuf[BUFLEN + 1];
    const size_t         buflen= BUFLEN;
    int                  retval;

    int			 dbg=SPF_get_debug( spfcid );
    int	res = 0;

    char *opt_ip = NULL;
    char *opt_sender = NULL;
    char *opt_helo = NULL;
/*    char *opt_rcpt_to = NULL; */


    char *p;

    SPF_id_t		spfid = NULL;
    SPF_output_t	spf_output;

    /* FIXME  should we be using a copy of the spfcid? */


    while( TRUE )
    {
	do
	    retval=GetOption(slave,&p,readbuf,buflen);
	while ( retval == 0 );
	if ( dbg > 0 )
	    fprintf( stderr, "< %s\n", readbuf );
	if ( retval == -1 )
	    break;
    

	/*
	 * commands
	 */
	if ( strcasecmp( p, "result" ) == 0 )
	{

	    spf_output = SPF_result( spfcid, spfdcid );

	    PrintfToSocket( slave, dbg, writebuf, buflen, "result=%s\n",
			    SPF_strresult( spf_output.result ) );
	    PrintfToSocket( slave, dbg, writebuf, buflen, "smtp_comment=%s\n",
			    spf_output.smtp_comment ? spf_output.smtp_comment : "" );
	    PrintfToSocket( slave, dbg, writebuf, buflen, "header_comment=%s\n",
			    spf_output.header_comment ? spf_output.header_comment : "" );
	    PrintfToSocket( slave, dbg, writebuf, buflen, "received_spf=%s\n",
			    spf_output.received_spf ? spf_output.received_spf : "" ); 
	    if ( dbg > 0 )
	    {
		fprintf( stderr, "err=%s (%d)\n",
			 SPF_strerror( spf_output.err ), spf_output.err );
		fprintf( stderr, "err_msg=%s\n",
			 spf_output.err_msg );
	    }
	    res = spf_output.result;

	    SPF_free_output( &spf_output );

	}
	else if ( strcasecmp( p, "quit" ) == 0 )
	{
	    break;
	}

	/* FIXME  more commands:  reset  result_2mx  help */

	/*
	 * options
	 */

	else if ( strncasecmp( p, "ip=", sizeof( "ip=" ) - 1 ) == 0 )
	{
	    opt_ip = p + sizeof( "ip=" ) - 1;

	    if ( SPF_set_ip_str( spfcid, opt_ip ) )
	    {
		PrintfToSocket( slave, dbg, writebuf, buflen, "Invalid IP address.\n" );
		res = 255;
		goto error;
	    }
	}
	else if ( strncasecmp( p, "helo=", sizeof( "helo=" ) - 1 ) == 0 )
	{
	    opt_helo = p + sizeof( "helo=" ) - 1;

	    if ( SPF_set_helo_dom( spfcid, opt_helo ) )
	    {
		PrintfToSocket( slave, dbg, writebuf, buflen, "Invalid HELO domain.\n" );
		res = 255;
		goto error;
	    }
	}
	else if ( strncasecmp( p, "sender=", sizeof( "sender=" ) - 1 ) == 0 )
	{
	    opt_sender = p + sizeof( "sender=" ) - 1;

	    if ( SPF_set_env_from( spfcid, opt_sender ) )
	    {
		PrintfToSocket( slave, dbg, writebuf, buflen, "Invalid envelope from address.\n" );
		res = 255;
		goto error;
	    }
	}

	/* FIXME  more options  all the options to spfquery */

	else 
	{
	    PrintfToSocket( slave, dbg, writebuf, buflen, "Invalid command or option.\n" );
	    res = 255;
	    goto error;
	}
	
    }

  error:
    if ( spfid ) SPF_destroy_id( spfid );
    
    return res;
}

/**************************************************************************/
/***************************************************************************

   WriteToSocket

   Write a buffer full of data to a socket. Keep writing until
   all the data has been put into the socket.

   sock         I               the socket to read from

   buffer       I               the buffer into which the data
                                is to be deposited

   buflen       I               the length of the buffer in bytes

   Returns: status code indicating success - 0 = success
  
***************************************************************************/
/**************************************************************************/

int WriteToSocket(const int sock,const char *const buffer,
                  const size_t buflen)
{
    size_t               bytesWritten=0;
    ssize_t              writeResult;
    int                  retval=0,done=0;

    do
    {
	writeResult=send(sock,buffer+bytesWritten,buflen-bytesWritten,0);
	if(writeResult==-1)
	{
	    if(errno==EINTR)
		writeResult=0;
	    else
            {
		retval=1;
		done=1;
            }
	}
	else
	{
	    bytesWritten+=writeResult;
	    if(writeResult==0)
		done=1;
	}
    }while(done==0);

    return retval;
}

/**************************************************************************/
/***************************************************************************

   PrintfToSocket

   Printf a formated string to a socket. Keep writing until
   all the data has been put into the socket.

   sock         I               the socket to read from

   buf          I               the buffer into which the data
                                is to be deposited

   buflen       I               the length of the buffer in bytes

   format       I               Format string

   args         I               Variables used by the format string

   Returns: status code indicating success - 0 = success
  
***************************************************************************/
/**************************************************************************/

int PrintfToSocket(const int sock,const int dbg,const char *const buffer,
		   const size_t buflen, const char *const format, ... )
{
    va_list		ap;
    size_t		len;
    

    va_start(ap,format);

    len = vsnprintf((char *)buffer,buflen,format,ap);
    
    if(dbg) printf("> %s",buffer);
    return WriteToSocket(sock,buffer,len);

    va_end(ap);
}

/**************************************************************************/
/***************************************************************************

   ReadLine

   Read a CRLF terminated line from a TCP socket. This is not
   the most efficient of functions, as it reads a byte at a
   time, but enhancements are beyond the scope of this example.

   sock         I               the socket to read from

   buffer       O               the buffer into which the data
                                is to be deposited

   buflen       I               the length of the buffer in bytes

   bytesRead    O               the amount of data read

   Returns: status code indicating success - 0 = success

***************************************************************************/
/**************************************************************************/

int ReadLine(const int sock,char *const buffer,const size_t buflen,
             size_t *const bytesRead)
{
    int                  done=0,retval=0;
    char                 c,lastC=0;
    size_t               bytesSoFar=0;
    ssize_t              readResult;
   
    do
    {
	readResult=recv(sock,&c,1,0);
      
	switch(readResult)
	{
	case -1:
	    if(errno!=EINTR)
	    {
		retval=-1;
		done=1;
	    }
	    break;
           
	case 0:
	    retval=0;
	    done=1;
	    break;
           
	case 1:
	    buffer[bytesSoFar]=c;
	    bytesSoFar+=readResult;
	    if(bytesSoFar>=buflen)
	    {
		done=1;
		retval=-1;
	    }
           
#if 0
	    if((c=='\n')&&(lastC=='\r'))
		done=1;
#else
	    if((c=='\n'))
		done=1;
#endif
	    lastC=c;
	    break;
	}
    }while(!done);
    buffer[bytesSoFar]=0;
    *bytesRead=bytesSoFar;
   
    return retval;
}

/**************************************************************************/
/***************************************************************************

   FatalSigHandler

   General catch-all signal handler to mop up signals that we aren't
   especially interested in. It shouldn't be called (if it is it
   probably indicates an error). It simply dumps a report of the
   signal to the log and dies. Note the strsignal() function may not be
   available on all platform/compiler combinations.

   sig          I               the signal number

   Returns: none
                                                                            
***************************************************************************/
/**************************************************************************/

void FatalSigHandler(int sig)
{
#ifdef _GNU_SOURCE
    syslog(LOG_MAIL|LOG_INFO,"caught signal: %s - exiting",strsignal(sig));
#else
    syslog(LOG_MAIL|LOG_INFO,"caught signal: %d - exiting",sig);
#endif

    closelog();
    TidyUp();
    _exit(0);
}

/**************************************************************************/
/***************************************************************************

   TermHandler

   Handler for the SIGTERM signal. It cleans up the lock file and
   closes the server's master socket, then immediately exits.

   sig          I               the signal number (SIGTERM)

   Returns: none
                                                                            
***************************************************************************/
/**************************************************************************/

void TermHandler(int sig __attribute__ ((unused)) )
{
    TidyUp();
    _exit(0);
}

/**************************************************************************/
/***************************************************************************

   HupHandler

   Handler for the SIGHUP signal. It sets the gGracefulShutdown and
   gCaughtHupSignal flags. The latter is used to distinguish this from
   catching SIGUSR1. Typically in real-world servers, SIGHUP is used to
   tell the server that it should re-read its configuration file. Many
   important daemons do this, including syslog and xinetd (under Linux).

   sig          I               the signal number (SIGTERM)

   Returns: none
                                                                            
***************************************************************************/
/**************************************************************************/

void HupHandler(int sig __attribute__ ((unused)) )
{
    syslog(LOG_MAIL|LOG_INFO,"caught SIGHUP");
    gGracefulShutdown=1;
    gCaughtHupSignal=1;

    /****************************************************************/
    /* perhaps at this point you would re-read a configuration file */
    /****************************************************************/

    return;
}

/**************************************************************************/
/***************************************************************************

   Usr1Handler

   Handler for the SIGUSR1 signal. This sets the gGracefulShutdown flag,
   which permits active connections to run to completion before shutdown.
   It is therefore a more friendly way to shut down the server than 
   sending SIGTERM.

   sig          I               the signal number (SIGTERM)

   Returns: none
                                                                            
***************************************************************************/
/**************************************************************************/

void Usr1Handler(int sig __attribute__ ((unused)) )
{
    syslog(LOG_MAIL|LOG_INFO,"caught SIGUSR1 - soft shutdown");
    gGracefulShutdown=1;

    return;
}

/**************************************************************************/
/***************************************************************************

   TidyUp

   Dispose of system resources. This function is not strictly necessary,
   as UNIX processes clean up after themselves (heap memory is freed,
   file descriptors are closed, etc.) but it is good practice to
   explicitly release that which you have allocated.

   Returns: none
                                                                            
***************************************************************************/
/**************************************************************************/

void TidyUp(void)
{
    if(gLockFileDesc!=-1)
    {
	close(gLockFileDesc);
	unlink(gLockFilePath);
	gLockFileDesc=-1;
    }

    if(gMasterSocket!=-1)
    {
	close(gMasterSocket);
	gMasterSocket=-1;
    }
}

/* FIXME  add doc block */


void wait_child(int sig __attribute__ ((unused)) )
{
    int status = 0;

    while (waitpid(-1, &status, WNOHANG) > 0)
	;

    signal(SIGCHLD, wait_child);
}
