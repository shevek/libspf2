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




#ifndef INC_SPF_DNS_RESOLV
#define INC_SPF_DNS_RESOLV

/* For an overview of the DNS layer system, see spf_dns.h */

/*
 * The resolv DNS layer is an interface to the libresolv stub DNS resolver.
 *
 * While multiple resolv DNS layers can be created, I can't see much
 * use for more than one.
 */

/*
 * These routines take care of creating/destroying/etc. the objects
 * that hold the DNS layer configuration.  spfdcid objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 */

/*
 * if debugging is enabled, information about the results from
 * libresolv will be displayed.  This information is often not passed
 * on to (and not needed by) the higher level DNS layers.
 */
SPF_dns_config_t SPF_dns_create_config_resolv( SPF_dns_config_t layer_below, int debug  );
void SPF_dns_reset_config_resolv( SPF_dns_config_t spfdcid );
void SPF_dns_destroy_config_resolv( SPF_dns_config_t spfdcid );


#endif
