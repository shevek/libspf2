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

#ifndef INC_SPF_REQUEST
#define INC_SPF_REQUEST

typedef struct SPF_request_struct SPF_request_t;

#include "spf_server.h"

struct SPF_request_struct {
	/* Structure variables */
	SPF_server_t	*spf_server;	/* The server. */

	/* Input client-end variables */
	int				 client_ver;	/* AF_INET/AF_INET6 */
	struct in_addr	 ipv4;			/* client (sending) MTA IP addr */
	struct in6_addr	 ipv6;			/* client (sending) MTA IP addr */
	char			*env_from;		/* envelope-from/MAIL FROM: */
	char			*helo_dom;		/* domain name from HELO cmd */
	char			*rcpt_to_dom;	/* RCPT TO: domain for 2mx  */

#if 0
	/* Input server-end variables */
	char			*rec_dom;		/* receiving MTA domain name */
#endif

	/* Per-request configuration variables */
	char			 use_local_policy;
	char			 use_helo;

	/* State/derived variables */
	char			*env_from_lp;	/* Local part of env_from */
	char			*env_from_dp;	/* Domain part of env_from */
	char			*client_dom;	/* Verified domain from client IP */

	/* I'm not sure whether this should be in here. */
	const char		*cur_dom;		/* "current domain" of SPF spec */
};

SPF_request_t	*SPF_request_new(SPF_server_t *spf_server);
void			 SPF_request_free(SPF_request_t *sr);
SPF_errcode_t	 SPF_request_set_ipv4(SPF_request_t *sr,
						struct in_addr addr);
SPF_errcode_t	 SPF_request_set_ipv6(SPF_request_t *sr,
						struct in6_addr addr);
SPF_errcode_t	 SPF_request_set_ipv4_str(SPF_request_t *sr,
						const char *astr);
SPF_errcode_t	 SPF_request_set_ipv6_str(SPF_request_t *sr,
						const char *astr);
SPF_errcode_t	 SPF_request_set_helo_dom(SPF_request_t *sr,
						const char *dom);
int				 SPF_request_set_env_from(SPF_request_t *sr,
						const char *from);
const char		*SPF_request_get_rec_dom(SPF_request_t *sr);

const char		*SPF_request_get_client_dom(SPF_request_t *sr);
int				 SPF_request_is_loopback(SPF_request_t *sr);

SPF_errcode_t	 SPF_request_query_mailfrom(SPF_request_t *spf_request,
						SPF_response_t **spf_responsep);
SPF_errcode_t	 SPF_request_query_rcptto(SPF_request_t *spf_request,
						SPF_response_t **spf_responsep,
						const char *rcpt_to);
SPF_errcode_t	 SPF_request_query_fallback(SPF_request_t *spf_request,
						SPF_response_t **spf_responsep,
						const char *record);


/* In spf_get_exp.c */
SPF_errcode_t	 SPF_request_get_exp(SPF_server_t *spf_server,
						SPF_request_t *spf_request,
						SPF_response_t *spf_response,
						SPF_record_t *spf_record,
						char **bufp, size_t *buflenp);

/* In spf_interpret.c - this is a kludge */

SPF_errcode_t	 SPF_i_done(SPF_response_t *spf_response,
						SPF_result_t result, SPF_reason_t reason,
						SPF_errcode_t err);


#endif
