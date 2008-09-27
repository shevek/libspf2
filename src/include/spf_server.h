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

#ifndef INC_SPF_SERVER
#define INC_SPF_SERVER

typedef struct SPF_server_struct SPF_server_t;

#include "spf_record.h"
#include "spf_dns.h"

#ifndef SPF_MAX_DNS_MECH
/* It is a bad idea to change this for two reasons.
 *
 * First, the obvious reason is the delays caused on the mail server
 * you are running.  DNS lookups that timeout can be *very* time
 * consuming, and even successful DNS lookups can take 200-500ms.
 * Many MTAs can't afford to wait long and even 2sec is pretty bad.
 *
 * The second, and more important reason, is the SPF records come from
 * a third party which may be malicious.  This third party can direct
 * DNS lookups to be sent to anyone.  If there isn't a limit, then it
 * is easy for someone to create a distributed denial of service
 * attack simply by sending a bunch of emails.  Unlike the delays on
 * your system caused by many DNS lookups, you might not even notice
 * that you are being used as part of a DDoS attack.
 */
#define SPF_MAX_DNS_MECH 10
#endif
#ifndef SPF_MAX_DNS_PTR
/* It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_PTR   10
#endif
#ifndef SPF_MAX_DNS_MX
/* It is a bad idea to change this for the same reasons as mentioned
 * above for SPF_MAX_DNS_MECH
 */
#define SPF_MAX_DNS_MX    10
#endif

struct SPF_server_struct {
	SPF_dns_server_t*resolver;		/**< SPF DNS resolver */
	SPF_record_t	*local_policy;	/**< Local policies */
	SPF_macro_t		*explanation;	/**< Explanation string */

	char			*rec_dom;		/**< Default receiving domain */

	int				 max_dns_mech;	/**< DoS limit on SPF mechanisms */
	int				 max_dns_ptr;	/**< DoS limit on PTR records */
	int				 max_dns_mx;	/**< DoS limit on MX records */

	int				 sanitize;		/**< limit charset in messages */
	int				 debug;			/**< print debug info */
};

typedef
enum SPF_server_dnstype_enum {
	SPF_DNS_RESOLV, SPF_DNS_CACHE, SPF_DNS_ZONE
} SPF_server_dnstype_t;

SPF_server_t	*SPF_server_new(SPF_server_dnstype_t dnstype,int debug);
void			 SPF_server_free(SPF_server_t *sp);
SPF_errcode_t	 SPF_server_set_rec_dom(SPF_server_t *sp,
					const char *dom);
SPF_errcode_t	 SPF_server_set_sanitize(SPF_server_t *sp,
					int sanitize);
SPF_errcode_t	 SPF_server_set_explanation(SPF_server_t *sp,
					const char *exp, SPF_response_t **spf_responsep);
SPF_errcode_t	 SPF_server_set_localpolicy(SPF_server_t *sp,
					const char *policy, int use_default_whitelist,
					SPF_response_t **spf_responsep);

SPF_errcode_t	 SPF_server_get_record(SPF_server_t *spf_server,
					SPF_request_t *spf_request,
					SPF_response_t *spf_response,
					SPF_record_t **spf_recordp);

/**
 * Prototypes for the various maximum accessors.
 */
#define SPF_DECL_ACCESS_INT(f) \
	SPF_errcode_t \
		SPF_server_set_ ## f(SPF_server_t *spf_server, int n); \
	int \
		SPF_server_get_ ## f(SPF_server_t *spf_server);

SPF_DECL_ACCESS_INT(max_dns_mech);
SPF_DECL_ACCESS_INT(max_dns_ptr);
SPF_DECL_ACCESS_INT(max_dns_mx);

#endif
