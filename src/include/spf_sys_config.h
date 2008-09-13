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




#ifndef INC_SPF_SYS_CONFIG
#define INC_SPF_SYS_CONFIG

#include "spf_win32_internal.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>			/* types (u_char .. etc..) */
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>		/* inet_ functions / structs */
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>		/* inet_ functions / structs */
#endif
#ifdef HAVE_ARPA_NAMESER_H
# ifdef HAVE_NS_TYPE
#  include <arpa/nameser.h>		/* DNS HEADER struct */
# else
/* looks like they have bind4/8 include files, use bind9 */
#  define HAVE_BIND8
#  include "../libreplace/arpa_nameser.h"
#  define HAVE_NS_TYPE 1		/* we have it now		*/
# endif
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>			/* in_addr struct */
#endif

#ifndef HAVE_U_INT8_T
# ifdef HAVE_UINT8_T
    typedef uint8_t u_int8_t;
# else
    typedef unsigned char u_int8_t;
# endif
#endif

#ifndef HAVE_U_INT16_T
# ifdef HAVE_UINT16_T
    typedef uint16_t u_int16_t;
# else
    typedef unsigned short u_int16_t;
# endif
#endif

#ifndef HAVE_U_INT32_T
# ifdef HAVE_UINT32_T
    typedef uint32_t u_int32_t;
# else
    typedef unsigned int u_int32_t;
# endif
#endif

#endif
