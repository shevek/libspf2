#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

// XXX Need to fix ns_type in spf_dns.h first.
// #include <arpa/nameser.h>

#include "../src/include/spf_server.h"
#include "../src/include/spf_request.h"
#include "../src/include/spf_response.h"
#include "../src/include/spf_dns_zone.h"

typedef SPF_server_t		*Mail__SPF_XS__Server;
typedef SPF_request_t		*Mail__SPF_XS__Request;
typedef SPF_response_t		*Mail__SPF_XS__Response;
typedef SPF_dns_server_t	*Mail__SPF_XS__Resolver;

#define EXPORT_INTEGER(x) do { \
								newCONSTSUB(stash, #x, newSViv(x)); \
								av_push(export, newSVpv(#x, strlen(#x))); \
						} while(0)

#define EXPORT_BIVALUE(x, p) do { \
							SV	*sv = newSViv(x); \
							sv_setpv(sv, p); \
							SvIOK_on(sv); \
							newCONSTSUB(stash, #x, sv); \
							av_push(export, newSVpv(#x, strlen(#x))); \
						} while(0)
#define EXPORT_ERRCODE(x) EXPORT_BIVALUE(x, SPF_strerror(x))

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS

PROTOTYPES: ENABLE

BOOT:
{
	HV      *stash;
	AV      *export;

	stash = gv_stashpv("Mail::SPF_XS", TRUE);
	export = get_av("Mail::SPF_XS::EXPORT_OK", TRUE);

	EXPORT_INTEGER(SPF_DNS_RESOLV);
	EXPORT_INTEGER(SPF_DNS_CACHE);
	EXPORT_INTEGER(SPF_DNS_ZONE);

	EXPORT_ERRCODE(SPF_E_SUCCESS);
	EXPORT_ERRCODE(SPF_E_NO_MEMORY);
	EXPORT_ERRCODE(SPF_E_NOT_SPF);
	EXPORT_ERRCODE(SPF_E_SYNTAX);
	EXPORT_ERRCODE(SPF_E_MOD_W_PREF);
	EXPORT_ERRCODE(SPF_E_INVALID_CHAR);
	EXPORT_ERRCODE(SPF_E_UNKNOWN_MECH);
	EXPORT_ERRCODE(SPF_E_INVALID_OPT);
	EXPORT_ERRCODE(SPF_E_INVALID_CIDR);
	EXPORT_ERRCODE(SPF_E_MISSING_OPT);
	EXPORT_ERRCODE(SPF_E_INTERNAL_ERROR);
	EXPORT_ERRCODE(SPF_E_INVALID_ESC);
	EXPORT_ERRCODE(SPF_E_INVALID_VAR);
	EXPORT_ERRCODE(SPF_E_BIG_SUBDOM);
	EXPORT_ERRCODE(SPF_E_INVALID_DELIM);
	EXPORT_ERRCODE(SPF_E_BIG_STRING);
	EXPORT_ERRCODE(SPF_E_BIG_MECH);
	EXPORT_ERRCODE(SPF_E_BIG_MOD);
	EXPORT_ERRCODE(SPF_E_BIG_DNS);
	EXPORT_ERRCODE(SPF_E_INVALID_IP4);
	EXPORT_ERRCODE(SPF_E_INVALID_IP6);
	EXPORT_ERRCODE(SPF_E_INVALID_PREFIX);
	EXPORT_ERRCODE(SPF_E_RESULT_UNKNOWN);
	EXPORT_ERRCODE(SPF_E_UNINIT_VAR);
	EXPORT_ERRCODE(SPF_E_MOD_NOT_FOUND);
	EXPORT_ERRCODE(SPF_E_NOT_CONFIG);
	EXPORT_ERRCODE(SPF_E_DNS_ERROR);
	EXPORT_ERRCODE(SPF_E_BAD_HOST_IP);
	EXPORT_ERRCODE(SPF_E_BAD_HOST_TLD);
	EXPORT_ERRCODE(SPF_E_MECH_AFTER_ALL);
	EXPORT_ERRCODE(SPF_E_INCLUDE_RETURNED_NONE);
	EXPORT_ERRCODE(SPF_E_RECURSIVE);

	EXPORT_INTEGER(SPF_RESULT_INVALID);
	EXPORT_INTEGER(SPF_RESULT_NEUTRAL);
	EXPORT_INTEGER(SPF_RESULT_PASS);
	EXPORT_INTEGER(SPF_RESULT_FAIL);
	EXPORT_INTEGER(SPF_RESULT_SOFTFAIL);

	EXPORT_INTEGER(SPF_RESULT_NONE);
	EXPORT_INTEGER(SPF_RESULT_TEMPERROR);
	EXPORT_INTEGER(SPF_RESULT_PERMERROR);

	// stash = gv_stashpv("Mail::SPF_XS::Resolver", TRUE);
	// export = get_av("Mail::SPF_XS::Resolver::EXPORT_OK", TRUE);

	EXPORT_INTEGER(ns_t_a);
	EXPORT_INTEGER(ns_t_any);
	EXPORT_INTEGER(ns_t_mx);
	EXPORT_INTEGER(ns_t_ns);
	EXPORT_INTEGER(ns_t_ptr);
	// EXPORT_INTEGER(ns_t_soa);
	EXPORT_INTEGER(ns_t_txt);

	EXPORT_INTEGER(NETDB_SUCCESS);
}

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Server

Mail::SPF_XS::Server
new(class, args)
	SV	*class
	HV	*args
	PREINIT:
		SPF_server_t	*spf_server;
		SV				**svp;
		SPF_server_dnstype_t	dnstype;
	CODE:
		(void)class;
		svp = hv_fetch(args, "dnstype", 7, FALSE);
		if (svp) {
			if (SvIOK(*svp))
				dnstype = SvIV(*svp);
			else
				croak("dnstype must be an integer");
		}
		else {
			dnstype = SPF_DNS_RESOLV;
		}
		spf_server = SPF_server_new(dnstype, 0);
		RETVAL = spf_server;
	OUTPUT:
		RETVAL

void
DESTROY(server)
	Mail::SPF_XS::Server	server
	CODE:
		SPF_server_free(server);

Mail::SPF_XS::Resolver
resolver(server)
	Mail::SPF_XS::Server	server
	CODE:
		RETVAL = server->resolver;
	OUTPUT:
		RETVAL

Mail::SPF_XS::Response
process(server, request)
	Mail::SPF_XS::Server	server
	Mail::SPF_XS::Request	request
	PREINIT:
		SPF_response_t	*response = NULL;
	CODE:
		request->spf_server = server;
		SPF_request_query_mailfrom(request, &response);
		RETVAL = response;
	OUTPUT:
		RETVAL

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Request

Mail::SPF_XS::Request
new(class, args)
	SV	*class
	HV	*args
	PREINIT:
		SV				**svp;
		SPF_request_t	*spf_request;
	CODE:
		(void)class;
		spf_request = SPF_request_new(NULL);
		svp = hv_fetch(args, "ip_address", 10, FALSE);
		if (!svp || !SvPOK(*svp))
			croak("new() requires ip_address => $address");
		if (SPF_request_set_ipv4_str(spf_request, SvPV_nolen(*svp)) != SPF_E_SUCCESS)
			if (SPF_request_set_ipv6_str(spf_request, SvPV_nolen(*svp)) != SPF_E_SUCCESS)
				croak("Failed to set client address: Not a valid ipv4 or ipv6");
		svp = hv_fetch(args, "identity", 8, FALSE);
		if (!svp || !SvPOK(*svp))
			croak("new() requires identity => $identity");
		if (SPF_request_set_env_from(spf_request, SvPV_nolen(*svp)) != 0)
			croak("Failed to set env_from identity");
		// ...
		RETVAL = spf_request;
	OUTPUT:
		RETVAL

void
DESTROY(request)
	Mail::SPF_XS::Request	request
	CODE:
		SPF_request_free(request);

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Response

void
DESTROY(response)
	Mail::SPF_XS::Response	response
	CODE:
		SPF_response_free(response);

const char *
code(response)
	Mail::SPF_XS::Response	response
	CODE:
		RETVAL = SPF_strresult(SPF_response_result(response));
	OUTPUT:
		RETVAL

const char *
reason(response)
	Mail::SPF_XS::Response	response
	CODE:
		RETVAL = SPF_strreason(SPF_response_reason(response));
	OUTPUT:
		RETVAL

const char *
error(response)
	Mail::SPF_XS::Response	response
	CODE:
		RETVAL = SPF_strerror(SPF_response_errcode(response));
	OUTPUT:
		RETVAL

const char *
explanation(response)
	Mail::SPF_XS::Response	response
	CODE:
		RETVAL = SPF_response_get_explanation(response);
		// RETVAL = response->smtp_comment;
	OUTPUT:
		RETVAL

SV *
string(response)
	Mail::SPF_XS::Response	response
	PREINIT:
		const char	*exp;
	CODE:
		if (response == NULL) {
			RETVAL = newSVpvf("(null)");
		}
		else {
			exp = SPF_response_get_explanation(response);
			RETVAL = newSVpvf("result=%s, reason=\"%s\", error=%s, explanation=\"%s\"",
						SPF_strresult(SPF_response_result(response)),
						SPF_strreason(SPF_response_reason(response)),
						SPF_strerror(SPF_response_errcode(response)),
						exp ? exp : "(null)");
		}
	OUTPUT:
		RETVAL

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Resolver

int
add(resolver, domain, rr_type, herrno, data)
	Mail::SPF_XS::Resolver	 resolver
	const char				*domain
	int						 rr_type
	int						 herrno
	const char				*data
	CODE:
		/* XXX Ensure it's a zone resolver. */
		RETVAL = SPF_dns_zone_add_str(resolver, domain, rr_type, herrno, data);
	OUTPUT:
		RETVAL

