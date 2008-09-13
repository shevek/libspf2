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




#ifndef INC_SPF_DNS_ZONE
#define INC_SPF_DNS_ZONE

/* For an overview of the DNS layer system, see spf_dns.h */

/*
 * The zone DNS layer allows you to create DNS zone information from
 * scratch, without calling some sort of external DNS resolver.
 *
 * The primary use is to either override real DNS information, or to
 * provide fallbacks when no DNS information is available.  The zone
 * will override the real DNS information if it is above the resolving
 * DNS layer in the stack.  It will provide a fallback if it is
 * layered below.
 *
 * The zone DNS layer supports wildcard domain names, but not in the
 * way that wilcards are supported in real DNS zones.  Unlike real DNS
 * zones, a wildcard in the zone layer will match even if there are
 * other records of a different RR type in the same zone.  This makes
 * wildcarding much more useful, but could cause confusion.
 *
 * When using wildcards, it is important to add the most specific DNS
 * zone data first, and the most general data last.  Otherwise, the
 * more general information will always be returned.  This should
 * probably be considered a bug and may be fixed in the future.
 *
 * For example, if you want to add entries with the same RR type for
 * "foo.foo.example.com", "*.foo.example.com" and "*.example.com", you
 * should add them in this order.
 *
 * You can also add entries with the RR type of ns_t_any, which will
 * match any type of RR query.  This is most useful when you want to
 * wildcard HOST_NOT_FOUND entries to prevent queries of any type from
 * being fetched from a lower DNS layer.
 */


/*
 * These routines take care of creating/destroying/etc. the objects
 * that hold the DNS layer configuration.  spfdcid objects contain
 * malloc'ed data, so they must be destroyed when you are finished
 * with them, or you will leak memory. 
 */

/*
 * The "name" will be used when displaying debugging information so
 * that you can tell which zone layer in the stack of DNS layers
 * generated the output.
 */
 
SPF_dns_server_t	*SPF_dns_zone_new(SPF_dns_server_t *layer_below,
				const char *name, int debug);

/*
 * If a given domain name has multiple records of a given RR type, you
 * can call the add routine multiple times to add to the RR set.
 */

SPF_errcode_t		 SPF_dns_zone_add_str(SPF_dns_server_t *spf_dns_server,
				const char *domain, ns_type rr_type,
				SPF_dns_stat_t herrno, const char *data);


#endif
