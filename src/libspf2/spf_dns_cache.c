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

#include "spf_sys_config.h"

#ifdef STDC_HEADERS
# include <stdio.h>        /* stdin / stdout */
# include <stdlib.h>       /* malloc / free */
#endif


#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif


#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_cache.h"


/*
 * this is really little more than a proof-of-concept cache.
 *
 * The cache size is fixed and uses the CRC-32 function as a hash
 * generator.  Little is done about hash collisions, no alternate hash
 * functions, no buckets, no linked lists, etc.  There is a small
 * reclaim list and if you add multiple DNS cache layers of different
 * sizes you get slightly different hash functions. (The CRC-32
 * function was chosen because I had a copy handy, it is pretty fast,
 * and single bit changes are guarenteed to give a different hash.
 * So, mx1.foo.com and mx2.foo.com will not collide)
 */


typedef struct
{
    int			debug;
    SPF_dns_rr_t	**cache;
    int			cache_size;
    int			hash_mask;
    int			max_hash_len;

    SPF_dns_rr_t	**reclaim;
    int			reclaim_size;
    int			reclaim_mask;

    int			hit;
    int			miss;

    time_t		min_ttl;
    time_t		err_ttl;
    time_t		txt_ttl;
    time_t		rdns_ttl;

    int			conserve_cache;

    SPF_dns_rr_t	nxdomain;
} SPF_dns_cache_config_t; 



/* FXIME  this isn't used.  shouldn't we use c_results anyway? */
typedef struct 
{
    int			hash;

    SPF_id_t		spfid;
    SPF_id_t		spfid_optimized;
    time_t		opt_utc_ttl;

    SPF_id_t		exp_id;
} SPF_dns_cache_data_t;
    


static inline SPF_dns_cache_config_t *SPF_voidp2spfhook( void *hook ) 
    { return (SPF_dns_cache_config_t *)hook; }
static inline void *SPF_spfhook2voidp( SPF_dns_cache_config_t *spfhook ) 
    { return (void *)spfhook; }


/*
** calculate CRC-32 stuff.
*/

/*
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 *
 *  First, the polynomial itself and its table of feedback terms.  The
 *  polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *
 *  Note that we take it "backwards" and put the highest-order term in
 *  the lowest-order bit.  The X^32 term is "implied"; the LSB is the
 *  X^31 term, etc.  The X^0 term (usually shown as "+1") results in
 *  the MSB being 1
 *
 *  Note that the usual hardware shift register implementation, which
 *  is what we're using (we're merely optimizing it by doing eight-bit
 *  chunks at a time) shifts bits into the lowest-order term.  In our
 *  implementation, that means shifting towards the right.  Why do we
 *  do it this way?  Because the calculated CRC must be transmitted in
 *  order from highest-order term to lowest-order term.  UARTs transmit
 *  characters in order from LSB to MSB.  By storing the CRC this way
 *  we hand it to the UART in the order low-byte to high-byte; the UART
 *  sends each low-bit to hight-bit; and the result is transmission bit
 *  by bit from highest- to lowest-order term without requiring any bit
 *  shuffling on our part.  Reception works similarly
 *
 *  The feedback terms table consists of 256, 32-bit entries.  Notes
 *
 *      The table can be generated at runtime if desired; code to do so
 *      is shown later.  It might not be obvious, but the feedback
 *      terms simply represent the results of eight shift/xor opera
 *      tions for all combinations of data and CRC register values
 *
 *      The values must be right-shifted by eight bits by the "updcrc
 *      logic; the shift must be unsigned (bring in zeroes).  On some
 *      hardware you could probably optimize the shift in assembler by
 *      using byte-swap instructions
 *      polynomial $edb88320
 */

const unsigned int crc_32_tab[256] = {
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
	0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
	0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
	0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
	0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
	0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
	0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
	0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
	0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
	0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
	0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
	0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
	0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
	0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
	0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
	0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
	0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
	0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
	0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
	0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
	0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
	0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
	0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
	0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
	0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
	0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
	0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
	0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
	0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
	0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
	0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
	0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
	0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
	0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
	0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
	0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
	0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
	0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
	0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
	0x2d02ef8dL
};

inline static int crc32str(unsigned int accum, const char *str, int max_hash_len )
{
    for( ; *str != '\0' && max_hash_len > 0; str++ )
    {
	if ( *str == '.' )
	    continue;
	
	accum = crc_32_tab[ (unsigned char)accum ^ (unsigned char)*str ]
	    ^ (unsigned char)(accum >> 8);

	max_hash_len--;
    }
    

   return(accum);
}

#define hash(h,s,a) (crc32str(a,s,h->max_hash_len) & (h->hash_mask))


static SPF_dns_rr_t *SPF_dns_lookup_cache( SPF_dns_config_t spfdcid, const char *domain, ns_type rr_type, int should_cache )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_cache_config_t	*spfhook = SPF_voidp2spfhook( spfdic->hook );

    SPF_dns_rr_t	*cached_rr, *reclaimed_rr, *fetched_rr;
    int			h, hr;
    time_t		t = 0;
    char		*p;


    /* see if the RR is in the cache */
    h = hash( spfhook, domain, spfhook->hash_mask + rr_type );
    cached_rr = spfhook->cache[ h ];
    
    if ( cached_rr
	 && cached_rr->rr_type == rr_type
	 && strcmp( cached_rr->domain, domain ) == 0
	 && cached_rr->utc_ttl >= (t = time( NULL )))
    {
	spfhook->hit++;
	if ( spfhook->debug > 1 )
	    SPF_debugf( "hit!  %d/%d  h: %d  should_cache: %d%s",
		spfhook->hit, spfhook->miss, h,
		should_cache, cached_rr == NULL ? "  cold" : "" 
	    );
	return cached_rr;
    }

    /* see if the RR is in the reclaim pool */
    hr = h & spfhook->reclaim_mask;
    reclaimed_rr = spfhook->reclaim[ hr ];
    
    if ( reclaimed_rr
	 && reclaimed_rr->rr_type == rr_type
	 && strcmp( reclaimed_rr->domain, domain ) == 0
	 && reclaimed_rr->utc_ttl >= (t ? t : (t = time( NULL ))))
    {
	spfhook->hit++;
	if ( spfhook->debug > 1 )
	    SPF_debugf( "hit!  %d/%d  h: %d  should_cache: %d%s  reclaimed",
		spfhook->hit, spfhook->miss, h,
		should_cache, cached_rr == NULL ? "  cold" : "" 
	    );

	spfhook->cache[ h ] = reclaimed_rr;
	spfhook->reclaim[ hr ] = cached_rr;

	return reclaimed_rr;
    }
    

    spfhook->miss++;
    if ( spfhook->debug > 1 )
	SPF_debugf( "miss...  %d/%d  h: %d  should_cache: %d%s",
		spfhook->hit, spfhook->miss, h,
		should_cache, cached_rr == NULL ? "  cold" : "" 
	    );

    

    if ( spfdic->layer_below )
	fetched_rr = SPF_dcid2spfdic( spfdic->layer_below )->lookup( spfdic->layer_below, domain, rr_type, should_cache );
    else
	return &spfhook->nxdomain;

    if ( spfhook->conserve_cache  &&  !should_cache )
	return fetched_rr;


    /* try to stash away the cached RR onto the reclaim pool */
    if ( cached_rr  &&  cached_rr->utc_ttl > (t ? t : (t = time( NULL ))))
    {
	if ( reclaimed_rr == NULL )
	    reclaimed_rr = SPF_dns_create_rr();
	if ( reclaimed_rr ) 
	{
	    if ( SPF_dns_copy_rr( reclaimed_rr, cached_rr ) == SPF_E_SUCCESS )
		spfhook->reclaim[ hr ] = reclaimed_rr;
	    else
	    {
		SPF_dns_destroy_rr( reclaimed_rr );
		reclaimed_rr = NULL;
	    }
	}
    }
    

    /* try to store the fetched RR into the cache */
    if ( cached_rr == NULL )
	cached_rr = SPF_dns_create_rr();
    if ( cached_rr == NULL )
	return fetched_rr;
    
    if ( SPF_dns_copy_rr( cached_rr, fetched_rr ) != SPF_E_SUCCESS )
    {
	SPF_dns_destroy_rr( cached_rr );
	return fetched_rr;
    }
    

    /* make sure the RR has enough data to be useful for caching */
    if ( cached_rr->rr_type == ns_t_any )
    {
	cached_rr->rr_type = rr_type;
	if ( cached_rr->domain ) cached_rr->domain[0] = '\0';
    }

    if ( cached_rr->domain == NULL  ||  cached_rr->domain[0] != '\0' )
    {
	char   *new_domain;
	size_t new_len = strlen( domain ) + 1;

	if ( cached_rr->domain_buf_len < new_len )
	{
	    new_domain = realloc( cached_rr->domain, new_len );
	    if ( new_domain == NULL )
	    {
		SPF_dns_destroy_rr( cached_rr );
		spfhook->cache[ h ] = NULL;
		return fetched_rr;
	    }

	    cached_rr->domain = new_domain;
	    cached_rr->domain_buf_len = new_len;
	}
	strcpy( cached_rr->domain, domain );
    }




    /* set up the ttl values */
    if ( cached_rr->ttl < spfhook->min_ttl )
	cached_rr->ttl = spfhook->min_ttl;

    if ( cached_rr->ttl < spfhook->txt_ttl
	 && cached_rr->rr_type == ns_t_txt )
	cached_rr->ttl = spfhook->txt_ttl;

    if ( cached_rr->ttl < spfhook->err_ttl
	 && cached_rr->herrno != NETDB_SUCCESS )
	cached_rr->ttl = spfhook->err_ttl;

    if ( cached_rr->ttl < spfhook->rdns_ttl )
    {
	p = strstr( cached_rr->domain, ".arpa" );
	if ( p && p[ sizeof( ".arpa" )-1 ] == '\0' )
	    cached_rr->ttl = spfhook->rdns_ttl;
    }

    if ( t == 0 ) t = time( NULL );
    cached_rr->utc_ttl = cached_rr->ttl + t;


    spfhook->cache[ h ] = cached_rr;

    return cached_rr;
}


SPF_dns_config_t SPF_dns_create_config_cache( SPF_dns_config_t layer_below, int cache_bits, int debug )
{
    SPF_dns_iconfig_t     *spfdic;
    SPF_dns_cache_config_t *spfhook;
    
    if ( layer_below == NULL )
	SPF_error( "layer_below is NULL." );

    if ( cache_bits < 1 || cache_bits > 16 )
	SPF_error( "cache bits out of range (1..16)." );
    

    spfdic = malloc( sizeof( *spfdic ) );
    if ( spfdic == NULL )
	return NULL;

    spfdic->hook = malloc( sizeof( SPF_dns_cache_config_t ) );
    if ( spfdic->hook == NULL )
    {
	free( spfdic );
	return NULL;
    }
    
    spfdic->destroy     = SPF_dns_destroy_config_cache;
    spfdic->lookup      = SPF_dns_lookup_cache;
#if 0
    /* FIXME  need to do more than just cache DNS records */
    spfdic->get_spf     = SPF_dns_get_spf_cache;
    spfdic->get_exp     = SPF_dns_get_exp_cache;
#else
    spfdic->get_spf     = NULL;
    spfdic->get_exp     = NULL;
    spfdic->add_cache   = NULL;
#endif
    spfdic->layer_below = layer_below;
    spfdic->name        = "cache";
    
    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->debug      = debug;

    spfhook->cache_size = 1 << cache_bits;
    spfhook->hash_mask  = spfhook->cache_size - 1;
    spfhook->max_hash_len = cache_bits > 4 ? cache_bits * 2 : 8;

    spfhook->reclaim_size = 1 << (cache_bits - 3); /* 8:1 overloading	*/
    if ( spfhook->reclaim_size <  1 ) spfhook->reclaim_size = 1;
    spfhook->reclaim_mask = spfhook->reclaim_size - 1;

    spfhook->cache = calloc( spfhook->cache_size, sizeof( *spfhook->cache ) );
    spfhook->reclaim = calloc( spfhook->reclaim_size, sizeof( *spfhook->reclaim ) );

    spfhook->hit        = 0;
    spfhook->miss       = 0;

    spfhook->min_ttl    = 30;
    spfhook->err_ttl    = 30*60;
    spfhook->txt_ttl    = 30*60;
    spfhook->rdns_ttl   = 30*60;
    spfhook->conserve_cache  = cache_bits < 12;

    if ( spfhook->cache == NULL )
    {
	free( spfdic );
	return NULL;
    }

    spfhook->nxdomain = SPF_dns_nxdomain;
    spfhook->nxdomain.source = SPF_spfdic2dcid( spfdic );
    
    return SPF_spfdic2dcid( spfdic );
}

void SPF_dns_reset_config_cache( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t		*spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_cache_config_t	*spfhook;
    int			i;

    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    spfhook = SPF_voidp2spfhook( spfdic->hook );
    if ( spfhook == NULL )
	SPF_error( "spfdcid.hook is NULL" );
	
    if ( spfhook->cache == NULL )
	SPF_error( "spfdcid.hook->cache is NULL" );
	
    if ( spfhook->reclaim == NULL )
	SPF_error( "spfdcid.hook->reclaim is NULL" );
	
    for( i = 0; i < spfhook->cache_size; i++ )
    {
	if ( spfhook->cache[i] )
	    SPF_dns_reset_rr( spfhook->cache[i] );
    }

    for( i = 0; i < spfhook->reclaim_size; i++ )
    {
	if ( spfhook->reclaim[i] )
	    SPF_dns_reset_rr( spfhook->reclaim[i] );
    }
}


void SPF_dns_set_ttl_cache( SPF_dns_config_t spfdcid, time_t min_ttl,
			    time_t err_ttl, time_t txt_ttl,
			    time_t rdns_ttl )
{
    SPF_dns_iconfig_t    *spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_cache_config_t *spfhook;


    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->min_ttl  = min_ttl;
    spfhook->err_ttl  = err_ttl;
    spfhook->txt_ttl  = txt_ttl;
    spfhook->rdns_ttl = rdns_ttl;
}


void SPF_dns_set_conserve_cache( SPF_dns_config_t spfdcid, int conserve_cache )
{
    SPF_dns_iconfig_t    *spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_cache_config_t *spfhook;


    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    spfhook = SPF_voidp2spfhook( spfdic->hook );

    spfhook->conserve_cache = conserve_cache;
}


void SPF_dns_destroy_config_cache( SPF_dns_config_t spfdcid )
{
    SPF_dns_iconfig_t     *spfdic = SPF_dcid2spfdic( spfdcid );
    SPF_dns_cache_config_t	*spfhook;
    int			i;


    if ( spfdcid == NULL )
	SPF_error( "spfdcid is NULL" );

    spfhook = SPF_voidp2spfhook( spfdic->hook );
    if ( spfhook )
    {
	for( i = 0; i < spfhook->cache_size; i++ )
	{
	    if ( spfhook->cache[i] )
		SPF_dns_destroy_rr( spfhook->cache[i] );
	}
	if ( spfhook->cache ) free( spfhook->cache );

	for( i = 0; i < spfhook->reclaim_size; i++ )
	{
	    if ( spfhook->reclaim[i] )
		SPF_dns_destroy_rr( spfhook->reclaim[i] );
	}
	if ( spfhook->reclaim ) free( spfhook->reclaim );

	free( spfhook );
    }
    
    free( spfdic );
}

