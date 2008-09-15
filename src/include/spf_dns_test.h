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




#ifndef INC_SPF_DNS_TEST
#define INC_SPF_DNS_TEST

#include "spf_dns.h"

/**
 * @file
 * @brief A testing layer for DNS.
 *
 * The test DNS layer is actually just a thin wrapper around the zone
 * DNS layer.  It provides all the DNS information needed to do the
 * SPF regression tests.  This happens to be useful to me when I'm
 * developing the library on my laptop and am not connected to the
 * net.
 *
 * While multiple test DNS layers can be created, I can't see any
 * use for more than one.
 *
 * For an overview of the DNS layer system, see spf_dns.h
 */

/**
 * These routines take care of creating/destroying/etc. the objects
 * that hold the DNS layer configuration. SPF_dns_server_t objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 */
SPF_dns_server_t	*SPF_dns_test_new( SPF_dns_server_t *layer_below,
				const char *name, int debug);

#endif
