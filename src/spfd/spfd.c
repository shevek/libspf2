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

#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h> /* DNS HEADER struct */
#endif

#include <sys/types.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_GETOPT_LONG_ONLY
#define _GNU_SOURCE
#include <getopt.h>
#else
#include "libreplace/getopt.h"
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

#include <pthread.h>

#include "spf.h"
#include "spf_dns.h"
#include "spf_dns_null.h"
#include "spf_dns_resolv.h"
#include "spf_dns_test.h"
#include "spf_dns_cache.h"


#define TRUE 1
#define FALSE 0

#define bool int

#define FREE(x, f) do { if ((x)) (f)((x)); (x) = NULL; } while(0)
#define FREE_REQUEST(x) FREE((x), SPF_request_free)
#define FREE_RESPONSE(x) FREE((x), SPF_response_free)
#define FREE_STRING(x) FREE((x), free)

typedef
struct _config_t {
	int		 tcpport;
	int		 udpport;
	char	*path;
#ifdef HAVE_PWD_H
	uid_t	 pathuser;
#endif
#ifdef HAVE_GRP_H
	gid_t	 pathgroup;
#endif
	int		 pathmode;
#ifdef HAVE_PWD_H
	uid_t	 setuser;
#endif
#ifdef HAVE_GRP_H
	gid_t	 setgroup;
#endif

	int		 debug;
	bool	 sec_mx;
	char	*fallback;

	char	*rec_dom;
	bool	 sanitize;
	int		 max_lookup;
	char	*localpolicy;
	bool	 use_trusted;
	char	*explanation;
	bool	 onerequest;
} config_t;

typedef
struct _request_t {
	int		 sock;
	union {
		struct sockaddr_in	in;
		struct sockaddr_un	un;
	} addr;
	socklen_t	 addrlen;
	char		*data;
	int			 datalen;

	char		*ip;
	char		*helo;
	char		*sender;
	char		*rcpt_to;

	SPF_errcode_t	 spf_err;
	SPF_request_t	*spf_request;
	SPF_response_t	*spf_response;

	char		 fmt[4096];
	int			 fmtlen;
} request_t;

typedef
struct _state_t {
	int	sock_udp;
	int	sock_tcp;
	int	sock_unix;
} state_t;

static SPF_server_t	*spf_server;
static config_t		 spfd_config;
static state_t		 spfd_state;

static void
response_print_errors(const char *context,
				SPF_response_t *spf_response, SPF_errcode_t err)
{
	SPF_error_t	*spf_error;
	int			 i;

	if (context != NULL)
		printf("Context: %s\n", context);
	if (err != SPF_E_SUCCESS)
		printf("ErrorCode: (%d) %s\n", err, SPF_strerror(err));

	if (spf_response != NULL) {
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			spf_error = SPF_response_message(spf_response, i);
			printf( "%s: %s%s\n",
					SPF_error_errorp(spf_error) ? "Error" : "Warning",
					((SPF_error_errorp(spf_error) && (!err))
							? "[UNRETURNED] "
							: ""),
					SPF_error_message(spf_error) );
		}
	}
	else {
		printf("Error: libspf2 gave a NULL spf_response");
	}
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

static const char *
request_check(request_t *req)
{
	const char	*msg = NULL;
	if (!req->ip)
		msg = "No IP address given";
	else if (!req->sender)
		msg = "No sender address given";
	else
		return NULL;
	snprintf(req->fmt, 4095,
		"result=unknown\n"
		"reason=%s\n",
		msg);
	return msg;
}

static void
request_query(request_t *req)
{
	SPF_request_t	*spf_request = NULL;
	SPF_response_t	*spf_response = NULL;
	SPF_response_t	*spf_response_2mx = NULL;
	SPF_errcode_t	 err;
	char			*p, *p_end;

#define UNLESS(x) err = (x); if (err)
// #define FAIL(x) do { response_print_errors((x), spf_response, err); goto fail; } while(0)
#define FAIL(x) do { goto fail; } while(0)
#define WARN(x, r) response_print_errors((x), (r), err)

	spf_request = SPF_request_new(spf_server);

	if (strchr(req->ip, ':')) {
		UNLESS(SPF_request_set_ipv6_str(spf_request, req->ip)) {
			FAIL("Setting IPv6 address");
		}
	}
	else {
		UNLESS(SPF_request_set_ipv4_str(spf_request, req->ip)) {
			FAIL("Setting IPv4 address");
		}
	}

	if (req->helo) {
		UNLESS(SPF_request_set_helo_dom(spf_request, req->helo)) {
			FAIL("Failed to set HELO domain");
		}
		/* XXX Set some flag saying to query on helo */
	}

	if (req->sender) {
		UNLESS(SPF_request_set_env_from(spf_request, req->sender)) {
			FAIL("Failed to set envelope-from address");
		}
		/* XXX Set some flag saying to query on sender */
	}

	/* XXX If flag not set, FAIL() */

	UNLESS(SPF_request_query_mailfrom(spf_request, &spf_response)) {
		FAIL("Failed to query based on mail-from address");
	}

	if (spfd_config.sec_mx) {
		if (req->rcpt_to && *req->rcpt_to) {
			p = req->rcpt_to;
			p_end = p + strcspn(p, " ,;");
			while (SPF_response_result(spf_response)!=SPF_RESULT_PASS) {
				if (*p_end)
					*p_end = '\0';
				else
					p_end = NULL;   /* Note this is last rcpt */
				UNLESS(SPF_request_query_rcptto(spf_request,
								&spf_response_2mx, p)) {
					WARN("Failed to query based on 2mx recipient",
									spf_response_2mx);
					FREE_RESPONSE(spf_response_2mx);
				}
				else {
					spf_response = SPF_response_combine(spf_response,
									spf_response_2mx);
					spf_response_2mx = NULL;	/* freed */
				}

				if (!p_end)
					break;
				p = p_end + 1;
			}
		}
	}

	if (spfd_config.fallback) {
		UNLESS(SPF_request_query_fallback(spf_request,
						&spf_response, spfd_config.fallback)) {
			FAIL("Querying fallback record");
		}
	}

	goto ok;

fail:
	req->spf_err = err;
	FREE_RESPONSE(spf_response);
	FREE_REQUEST(spf_request);

ok:
	// response_print("Result: ", spf_response);
	(void)response_print;

	req->spf_response = spf_response;
	req->spf_request = spf_request;
}

/* This is needed on HP/UX, IIRC */
static inline const char *
W(const char *c)
{
	if (c)
		return c;
	return "(null)";
}

static void
request_format(request_t *req)
{
	SPF_response_t	*spf_response;

	spf_response = req->spf_response;

	if (spf_response) {
		req->fmtlen = snprintf(req->fmt, 4095,
			"ip=%s\n"
			"sender=%s\n"
			"result=%s\n"
			"reason=%s\n"
			"smtp_comment=%s\n"
			"header_comment=%s\n"
			"error=%s\n"
			, req->ip, req->sender
			, W(SPF_strresult(SPF_response_result(spf_response)))
			, W(SPF_strreason(SPF_response_reason(spf_response)))
			, W(SPF_response_get_smtp_comment(spf_response))
			, W(SPF_response_get_header_comment(spf_response))
			, W(SPF_strerror(SPF_response_errcode(spf_response)))
			);
	}
	else {
		req->fmtlen = snprintf(req->fmt, 4095,
			"ip=%s\n"
			"sender=%s\n"
			"result=unknown\n"
			"error=%s\n"
			, req->ip, req->sender
			, SPF_strerror(req->spf_err)
			);
	}

	req->fmt[4095] = '\0';
}

static void
request_handle(request_t *req)
{
	printf("| %s\n", req->sender); fflush(stdout);
	if (!request_check(req)) {
		request_query(req);
		request_format(req);
	}
	// printf("==\n%s\n", req->fmt);
}

static const struct option longopts[] = {
	{ "debug",		required_argument,	NULL,	'd', },
	{ "tcpport",	required_argument,	NULL,	't', },
	{ "udpport",	required_argument,	NULL,	'p', },
	{ "path",		required_argument,	NULL,	'f', },
#ifdef HAVE_PWD_H
	{ "pathuser",	required_argument,	NULL,	'x', },
#endif
#ifdef HAVE_GRP_H
	{ "pathgroup",	required_argument,	NULL,	'y', },
#endif
	{ "pathmode",	required_argument,	NULL,	'm', },
#ifdef HAVE_PWD_H
	{ "setuser",	required_argument,	NULL,	'u', },
#endif
#ifdef HAVE_GRP_H
	{ "setgroup",	required_argument,	NULL,	'g', },
#endif
	{ "onerequest",	no_argument,		NULL,	'o', },
	{ "help",       no_argument,		NULL,	'h', },
};

static const char *shortopts = "d:t:p:f:x:y:m:u:g:h:";

void usage (void) {
	fprintf(stdout,"Flags\n");
	fprintf(stdout,"\t-tcpport\n");
	fprintf(stdout,"\t-udpport\n");
	fprintf(stdout,"\t-path\n");
#ifdef HAVE_PWD_H
	fprintf(stdout,"\t-pathuser\n");
#endif
#ifdef HAVE_GRP_H
	fprintf(stdout,"\t-pathgroup\n");
#endif
	fprintf(stdout,"\t-pathmode\n");
#ifdef HAVE_PWD_H
	fprintf(stdout,"\t-setuser\n");
#endif
#ifdef HAVE_GRP_H
	fprintf(stdout,"\t-setgroup\n");
#endif
	fprintf(stdout,"\t-onerequest\n");
	fprintf(stdout,"\t-help\n");

}

#define DIE(x) do { fprintf(stderr, "%s\n", x); exit(1); } while(0)

#ifdef HAVE_PWD_H
static gid_t
daemon_get_user(const char *arg)
{
	struct passwd	*pwd;
	if (isdigit(arg[0]))
		pwd = getpwuid(atol(arg));
	else
		pwd = getpwnam(arg);
	if (pwd == NULL) {
		fprintf(stderr, "Failed to find user %s\n", arg);
		DIE("Unknown user");
	}
	return pwd->pw_uid;
}
#endif

#ifdef HAVE_GRP_H
static gid_t
daemon_get_group(const char *arg)
{
	struct group	*grp;
	if (isdigit(arg[0]))
		grp = getgrgid(atol(arg));
	else
		grp = getgrnam(arg);
	if (grp == NULL) {
		fprintf(stderr, "Failed to find user %s\n", arg);
		DIE("Unknown group");
	}
	return grp->gr_gid;
}
#endif

static void
daemon_config(int argc, char *argv[])
{
	int		 idx;
	char	 c;

	memset(&spfd_config, 0, sizeof(spfd_config));

	while ((c =
		getopt_long(argc, argv, shortopts, longopts, &idx)
			) != -1) {
		switch (c) {
			case 't':
				spfd_config.tcpport = atol(optarg);
				break;
			case 'p':
				spfd_config.udpport = atol(optarg);
				break;
			case 'f':
				spfd_config.path = optarg;
				break;

			case 'd':
				spfd_config.debug = atol(optarg);
				break;

#ifdef HAVE_PWD_H
			case 'x':
				spfd_config.pathuser = daemon_get_user(optarg);
				break;
#endif
#ifdef HAVE_GRP_H
			case 'y':
				spfd_config.pathgroup = daemon_get_group(optarg);
				break;
#endif

			case 'm':
				spfd_config.pathmode = atol(optarg);
				break;

#ifdef HAVE_PWD_H
			case 'u':
				spfd_config.setuser = daemon_get_user(optarg);
				break;
#endif
#ifdef HAVE_GRP_H
			case 'g':
				spfd_config.setgroup = daemon_get_group(optarg);
				break;
#endif
			case 'o':
				spfd_config.onerequest = 1;
				fprintf(stdout, "One request mode\n");
				break;

			case 0:
			case '?':
				usage();
				DIE("Invalid argument");
				break;
			case 'h' :
				usage();
				DIE("");
				break;

			default:
				fprintf(stderr, "Error: getopt returned character code 0%o ??\n", c);
				DIE("WHAT?");
		}
	}
}

static int
daemon_bind_inet_udp()
{
	struct sockaddr_in	 addr;
	int					 sock;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		DIE("Failed to create socket");
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(spfd_config.udpport);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, (struct sockaddr *)(&addr), sizeof(addr)) < 0) {
		perror("bind");
		DIE("Failed to bind socket");
	}

	fprintf(stderr, "Accepting datagrams on %d\n", spfd_config.udpport);

	return sock;
}

static int
daemon_bind_inet_tcp()
{
	struct sockaddr_in	 addr;
	int					 sock;

	int					 optval;
	size_t				 optlen;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		DIE("Failed to create socket");
	}

	optval = 1;
	optlen = sizeof(int);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(spfd_config.tcpport);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, (struct sockaddr *)(&addr), sizeof(addr)) < 0) {
		perror("bind");
		DIE("Failed to bind socket");
	}

	if (listen(sock, 5) < 0) {
		perror("listen");
		DIE("Failed to listen on socket");
	}

	fprintf(stderr, "Accepting connections on %d\n", spfd_config.tcpport);

	return sock;
}

static int
daemon_bind_unix()
{
	struct sockaddr_un	 addr;
	int					 sock;

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		DIE("Failed to create socket");
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, spfd_config.path, sizeof(addr.sun_path) - 1);
	if (unlink(spfd_config.path) < 0) {
		if (errno != ENOENT) {
			perror("unlink");
			DIE("Failed to unlink socket");
		}
	}
	if (bind(sock, (struct sockaddr *)(&addr), sizeof(addr)) < 0) {
		perror("bind");
		DIE("Failed to bind socket");
	}
	if (listen(sock, 5) < 0) {
		perror("listen");
		DIE("Failed to listen on socket");
	}

	fprintf(stderr, "Accepting connections on %s\n", spfd_config.path);

	return sock;
}

static void
daemon_init()
{
	SPF_response_t	*spf_response = NULL;
	SPF_errcode_t	 err;

	memset(&spfd_state, 0, sizeof(spfd_state));

	spf_server = SPF_server_new(SPF_DNS_CACHE, spfd_config.debug);

	if (spfd_config.rec_dom) {
		UNLESS(SPF_server_set_rec_dom(spf_server,
						spfd_config.rec_dom)) {
			DIE("Failed to set receiving domain name");
		}
	}

	if (spfd_config.sanitize) {
		UNLESS(SPF_server_set_sanitize(spf_server,
						spfd_config.sanitize)) {
			DIE("Failed to set server sanitize flag");
		}
	}

	if (spfd_config.max_lookup) {
		UNLESS(SPF_server_set_max_dns_mech(spf_server,
						spfd_config.max_lookup)){
			DIE("Failed to set maximum DNS requests");
		}
	}

	if (spfd_config.localpolicy) {
		UNLESS(SPF_server_set_localpolicy(spf_server,
						spfd_config.localpolicy,
						spfd_config.use_trusted,
						&spf_response)){
			response_print_errors("Compiling local policy",
							spf_response, err);
			DIE("Failed to set local policy");
		}
		FREE_RESPONSE(spf_response);
	}

	if (spfd_config.explanation) {
		UNLESS(SPF_server_set_explanation(spf_server,
						spfd_config.explanation,
						&spf_response)){
			response_print_errors("Setting default explanation",
							spf_response, err);
			DIE("Failed to set default explanation");
		}
		FREE_RESPONSE(spf_response);
	}

	if (spfd_config.udpport)
		spfd_state.sock_udp = daemon_bind_inet_udp();
	if (spfd_config.tcpport)
		spfd_state.sock_tcp = daemon_bind_inet_tcp();
	if (spfd_config.path)
		spfd_state.sock_unix = daemon_bind_unix();
	/* XXX Die if none of the above. */
}

/* This has a return value so we can decide whether to malloc and/or
 * free in the caller. */
static char **
find_field(request_t *req, const char *key)
{
#define STREQ(a, b) (strcmp((a), (b)) == 0)

	if (STREQ(key, "ip"))
		return &req->ip;
	if (STREQ(key, "helo"))
		return &req->helo;
	if (STREQ(key, "sender"))
		return &req->sender;
	if (STREQ(key, "rcpt"))
		return &req->rcpt_to;
	fprintf(stderr, "Invalid key %s\n", key);
	return NULL;
}

/* This is called with req->data malloc'd */
static void *
handle_datagram(void *arg)
{
	request_t	*req;
	char		**fp;
	char		*key;
	char		*value;
	char		*end;
	int			 err;

	req = (request_t *)arg;
	key = req->data;

	// printf("req: %s\n", key);

	while (key < (req->data + req->datalen)) {
		end = key + strcspn(key, "\r\n");
		*end = '\0';
		value = strchr(key, '=');

		/* Did that line contain an '='? */
		if (!value)	/* XXX WARN */
			continue;

		*value++ = '\0';
		fp = find_field(req, key);
		if (fp != NULL)
			*fp = value;
		else
			/* warned already */ ;

		key = end + 1;
		while (key < (req->data + req->datalen)) {
			if (strchr("\r\n", *key))
				key++;
			else
				break;
		}
	}

	request_handle(req);

#ifdef DEBUG
	printf("Target address length is %d: %s:%d\n", req->addrlen,
					inet_ntoa(req->addr.in.sin_addr),
					req->addr.in.sin_port);
#endif

	printf("- %s\n", req->sender); fflush(stdout);
	err = sendto(req->sock, req->fmt, req->fmtlen, 0,
			(struct sockaddr *)(&req->addr.in), req->addrlen);
	if (err == -1)
		perror("sendto");

	FREE_RESPONSE(req->spf_response);
	FREE_REQUEST(req->spf_request);

	FREE_STRING(req->data);
	free(arg);
	return NULL;
}

/* Only req is malloc'd in this. */
static void *
handle_stream(void *arg)
{
	request_t	*req;
	char		**fp;
	FILE		*stream;
	char		 key[BUFSIZ];
	char		*value;
	char		*end;

	req = (request_t *)arg;
	stream = fdopen(req->sock, "r");

	do {
		while (fgets(key, BUFSIZ, stream) != NULL) {
			key[strcspn(key, "\r\n")] = '\0';

			/* Break on a blank line and permit another query */
			if (*key == '\0')
				break;

			end = key + strcspn(key, "\r\n");
			*end = '\0';
			value = strchr(key, '=');

			if (!value)	/* XXX WARN */
				continue;

			*value++ = '\0';
			fp = find_field(req, key);
			if (fp != NULL)
				*fp = strdup(value);
			else
				/* warned already */ ;
		}

		request_handle(req);

		printf("- %s\n", req->sender); fflush(stdout);
		send(req->sock, req->fmt, req->fmtlen, 0);

		FREE_STRING(req->ip);
		FREE_STRING(req->helo);
		FREE_STRING(req->sender);
		FREE_STRING(req->rcpt_to);
	} while (! (spfd_config.onerequest || feof(stream)));

	shutdown(req->sock, SHUT_RDWR);
	fclose(stream);

	free(arg);
	return NULL;
}

static void
daemon_main()
{
	pthread_attr_t	 attr;
	pthread_t		 th;

	request_t		*req;
	char			 buf[4096];
	fd_set			 rfd;
	fd_set			 sfd;
	int				 maxfd;


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	FD_ZERO(&rfd);
	maxfd = 0;

	if (spfd_state.sock_udp) {
		// printf("UDP socket is %d\n", spfd_state.sock_udp);
		FD_SET(spfd_state.sock_udp, &rfd);
		if (spfd_state.sock_udp > maxfd)
			maxfd = spfd_state.sock_udp;
	}
	if (spfd_state.sock_tcp) {
		// printf("TCP socket is %d\n", spfd_state.sock_tcp);
		FD_SET(spfd_state.sock_tcp, &rfd);
		if (spfd_state.sock_tcp > maxfd)
			maxfd = spfd_state.sock_tcp;
	}
	if (spfd_state.sock_unix) {
		// printf("UNIX socket is %d\n", spfd_state.sock_unix);
		FD_SET(spfd_state.sock_unix, &rfd);
		if (spfd_state.sock_unix > maxfd)
			maxfd = spfd_state.sock_unix;
	}
	// printf("MaxFD is %d\n", maxfd);

#define NEW_REQUEST	((request_t *)calloc(1, sizeof(request_t)));

	for (;;) {
		memcpy(&sfd, &rfd, sizeof(rfd));
		if (select(maxfd + 1, &sfd, NULL, NULL, NULL) == -1)
			break;

		if (spfd_state.sock_udp) {
			if (FD_ISSET(spfd_state.sock_udp, &sfd)) {
				req = NEW_REQUEST;
				req->addrlen = sizeof(req->addr);
				// printf("UDP\n");
				req->sock = spfd_state.sock_udp;
				req->datalen = recvfrom(spfd_state.sock_udp, buf,4095,0,
					(struct sockaddr *)(&req->addr.in), &req->addrlen);
				if (req->datalen >= 0) {
					buf[req->datalen] = '\0';
					req->data = strdup(buf);
					pthread_create(&th, &attr, handle_datagram, req);
				}
				else {
					free(req);
				}
			}
		}
		if (spfd_state.sock_tcp) {
			if (FD_ISSET(spfd_state.sock_tcp, &sfd)) {
				req = NEW_REQUEST;
				req->addrlen = sizeof(req->addr);
				// printf("TCP\n");
				req->sock = accept(spfd_state.sock_tcp,
					(struct sockaddr *)(&req->addr.in), &req->addrlen);
				if (req->sock >= 0)
					pthread_create(&th, &attr, handle_stream, req);
				else
					free(req);
			}
		}
		if (spfd_state.sock_unix) {
			if (FD_ISSET(spfd_state.sock_unix, &sfd)) {
				req = NEW_REQUEST;
				req->addrlen = sizeof(req->addr);
				// printf("UNIX\n");
				req->sock = accept(spfd_state.sock_unix,
					(struct sockaddr *)(&req->addr.un), &req->addrlen);
				if (req->sock >= 0)
					pthread_create(&th, &attr, handle_stream, req);
				else
					free(req);
			}
		}
	}

	pthread_attr_destroy(&attr);
}

int
main(int argc, char *argv[])
{
	daemon_config(argc, argv);
	daemon_init();
	daemon_main();
	return 0;
}
