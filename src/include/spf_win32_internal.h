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


#ifdef _WIN32

#ifndef INC_SPF_WIN32_INTERNAL
#define INC_SPF_WIN32_INTERNAL

#include "spf_win32.h"

#define STDC_HEADERS

#define inline __inline

#define NETDB_SUCCESS   ERROR_SUCCESS

#define IN_LOOPBACKNET 127

#define snprintf _snprintf
#define vsnprintf _vsnprintf 

char *inet_ntop(int af, const void *src, char *dst, size_t size);
int inet_pton(int af, const char *src, void *dst);

int gethostnameFQDN(char* name, int namelen);

#endif

#endif
