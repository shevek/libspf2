#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "../src/include/spf_server.h"
#include "../src/include/spf_request.h"
#include "../src/include/spf_response.h"

typedef SPF_server_t	*Mail__SPF_XS__Server;
typedef SPF_request_t	*Mail__SPF_XS__Request;
typedef SPF_response_t	*Mail__SPF_XS__Response;

#define EXPORT_INTEGER(x) do { \
								newCONSTSUB(stash, #x, newSViv(x)); \
								av_push(export, newSVpv(#x, strlen(#x))); \
						} while(0)

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
}

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Server

Mail::SPF_XS::Server
new(class, args)
	SV	*class
	HV	*args
	PREINIT:
		SPF_server_t	*spf_server;
	CODE:
		(void)class;
		spf_server = NULL;
		RETVAL = spf_server;
	OUTPUT:
		RETVAL

void
DESTROY(server)
	Mail::SPF_XS::Server	server
	CODE:
		SPF_server_free(server);

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Request

Mail::SPF_XS::Request
new(server, args)
	Mail::SPF_XS::Server	 server
	HV						*args
	PREINIT:
		// SV				**svp;
		SPF_request_t	*spf_request;
	CODE:
		spf_request = SPF_request_new(server);
		RETVAL = spf_request;
	OUTPUT:
		RETVAL

void
DESTROY(request)
	Mail::SPF_XS::Request	request
	CODE:
		SPF_request_free(request);

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Response
