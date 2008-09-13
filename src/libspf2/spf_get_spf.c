/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 * 
 *   a) The GNU Lesser General Public License as published by the Free
 *	  Software Foundation; either version 2.1, or (at your option) any
 *	  later version,
 * 
 *   OR
 * 
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */

#include "spf_sys_config.h"

#ifdef STDC_HEADERS
# include <stdio.h>		/* stdin / stdout */
# include <stdlib.h>	   /* malloc / free */
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>	   /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>	   /* strstr / strdup */
# endif
#endif



#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"

/* domain == spf_request->cur_dom */
