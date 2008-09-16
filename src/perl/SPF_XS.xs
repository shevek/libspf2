#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "../include/spf_server.h"

typedef SPF_server_t	*Mail__SPF_XS__Server;

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS

PROTOTYPES: ENABLE

BOOT:
{
}

MODULE = Mail::SPF_XS	PACKAGE = Mail::SPF_XS::Server

Mail::SPF_XS::Server
new(class, args)
	SV	*class
	HV	*args
	PREINIT:
		SPF_server_t	*spf_server;
	CODE:
		spf_server = NULL;
		RETVAL = spf_server;
	OUTPUT:
		RETVAL
