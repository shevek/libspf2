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




#ifndef INC_SPF_DNS_CACHE
#define INC_SPF_DNS_CACHE


/**
 * @file
 *
 * The caching DNS layer provides a quick, in-process cache of DNS
 * information.  It is not designed to be a general DNS cache, it is
 * tailored to the needs of the SPF system.  In particular, you can
 * cache compiled SPF records, thus reducing the need to constantly
 * recompile commonly used ones.
 *
 * In most cases, it is best to have at least a small DNS caching
 * layer as the top layer.
 *
 * Multiple caching DNS layers can be created, which could sometimes
 * be useful.  For example, caches of different sizes will have
 * different hash collisions, thus reducing the number of redundant
 * queries sent to lower DNS layers.
 *
 *
 * For an overview of the DNS layer system, see spf_dns.h
 */


/**
 * These routines take care of creating/destroying/etc. the objects
 * that hold the DNS layer configuration. SPF_dns_server_t objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 *
 * cache_bits determines the size of the DNS cache.  The cache will be
 * 2^cache_bits entries large.
 *
 * If debugging is turned on, information about cache hits and misses
 * will be generated.
 */
SPF_dns_server_t	*SPF_dns_cache_new(SPF_dns_server_t *layer_below,
				const char *name, int debug, int cache_bits);


/**
 * By default, the caching DNS layer uses the Time To Live (TTL)
 * values that are obtained from the actual DNS Resource Records (RR).
 * However, because we know more about the situation than general
 * caching DNS resolvers, we can adjusted the TTLs to be more
 * appropriate for the email system.  For example, since DNS errors
 * will cause a 4xx temporary failure to be returned by the MTA, and
 * the RFCs require the sending MTA to wait a while before it tries to
 * resend the message, we can cache DNS errors for a while.  General
 * caching resolvers can't know if the next request needs the latest
 * information about a name server being down, so it doesn't cache
 * this information.
 *
 * The caching DNS layer allows the following minimal TTL values:
 *
 * min_ttl	The absolute minimum TTL value in all cases.
 *
 * err_ttl	The minimum TTL value to use when there is a DNS error.
 *
 * txt_ttl	The minimum TTL value to use when a TXT query is done.
 *              In the case of SPF, these are the SPF records and the
 *		explanation records.  This TTL value is used even when
 *		no record is found, so domains that haven't set up SPF
 *		records won't be constantly queried.  Since SPF
 *		records are intended to not be changed often, this
 *		value can be fairly large.
 *
 * rdns_ttl	The minimum TTL value to use when looking up information
 *		in the reverse DNS tree.  This applies to both valid
 *		results, and when an error is detected.
 *
 * Note that more than one of these TTL values may apply.  A TXT RR
 * lookup that fails will have a TTL that is the largest of the
 * min_ttl, the err_ttl and the txt_ttl values.
 * 
 */

void	 SPF_dns_cache_set_ttl( SPF_dns_server_t *spf_dns_server,
				time_t min_ttl, time_t err_ttl,
				time_t txt_ttl, time_t rdns_ttl );

/**
 * The caching DNS layer can try to conserve it's cache to only those
 * queries that will likely to be used often.  If told to conserve the
 * cache entries, it will not cache queries that were constructed from
 * things like the client IP address or the local part of the
 * envelope-from email address.  Such information may well be cached
 * by the general DNS resolver, so the answers may be quickly obtained
 * anyway.
 *
 * By default, caches with fewer than 4k entries (12 bits) will try to
 * conserve the cache entries, but larger caches will not.  This is
 * just a guess though.  In reality, it will depend a great deal on
 * how active your mail server is and what the typical TTL values that
 * you get from the particular DNS records you query are.
 */

void	 SPF_dns_set_conserve_cache( SPF_dns_server_t *spf_dns_server,
				int conserve_cache );

#endif
