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




#ifndef INC_SPF_DNS_NULL
#define INC_SPF_DNS_NULL

/* For an overview of the DNS layer system, see spf_dns.h */

/* The null DNS layer is really just a minimal DNS layer.  It is
 * useful when you don't want to do any real DNS lookups, or when you
 * want to be able to get debugging information about the requests
 * flowing between DNS layers.
 *
 * Multiple null DNS layers can be created, which can be useful for
 * debugging purposes.
 */


/*
 * These routines take care of creating/destroying/etc. the objects
 * that hold the DNS layer configuration.  spfdcid objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 */

/*
 * if debugging is enabled, information about the DNS queries sent to
 * the lower DNS layer, and the results returned from that layer will
 * be displayed.
 *
 * The "name" will be used when displaying debugging information so
 * that you can tell which location in the stack of DNS layers
 * generated the output.
 */
 
SPF_dns_config_t SPF_dns_create_config_null( SPF_dns_config_t layer_below, int debug, const char *name );
void SPF_dns_reset_config_null( SPF_dns_config_t spfdcid );
void SPF_dns_destroy_config_null( SPF_dns_config_t spfdcid );


#endif
