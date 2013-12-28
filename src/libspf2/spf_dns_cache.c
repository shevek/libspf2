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

#ifdef HAVE_PTHREAD_H
# include <pthread.h>
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_cache.h"


/**
 * @file
 *
 * Implements a simple cache using a list hash. There is no reclaim
 * list, since GNU malloc has clue.
 *
 * This original description from Wayne is no longer true:
 *
 * This is really little more than a proof-of-concept cache.
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


typedef
struct _SPF_dns_cache_bucket_t {
	struct _SPF_dns_cache_bucket_t	*next;
	SPF_dns_rr_t					*rr;
} SPF_dns_cache_bucket_t;

typedef struct
{
    SPF_dns_cache_bucket_t	**cache;
    int						  cache_size;
    pthread_mutex_t			  cache_lock;

    int				hash_mask;
    int				max_hash_len;

#if 0
    int				hit;
    int				miss;
#endif

    time_t			min_ttl;
    time_t			err_ttl;
    time_t			txt_ttl;
    time_t			rdns_ttl;

    int				conserve_cache;

    
} SPF_dns_cache_config_t;


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

static inline int
crc32str(unsigned int accum, const char *str, int max_hash_len)
{
    for( ; *str != '\0' && max_hash_len > 0; str++ ) {
		if ( *str == '.' )
			continue;

		accum = crc_32_tab[ (unsigned char)accum ^ (unsigned char)*str ]
			^ (unsigned char)(accum >> 8);

		max_hash_len--;
	}


	return accum;
}

// #define hash(h,s,a) (crc32str(a,s,h->max_hash_len) & (h->hash_mask))
#define hash(h,s,a) crc32str(a,s,h->max_hash_len)

/* This must be called with the lock held. */
static SPF_dns_cache_bucket_t *
SPF_dns_cache_bucket_find(SPF_dns_cache_config_t *spfhook,
				const char *domain, ns_type rr_type, int idx)
{
	SPF_dns_cache_bucket_t	*bucket;
	SPF_dns_cache_bucket_t	*prev;
	SPF_dns_rr_t			*rr;
	time_t					 now;

    bucket = spfhook->cache[idx];
	prev = NULL;
	time(&now);

	while (bucket != NULL) {
		rr = bucket->rr;

		if (rr->utc_ttl < now) {
			/* Unlink the bucket. */
			if (prev != NULL)
				prev->next = bucket->next;
			else
				spfhook->cache[idx] = bucket->next;
			/* Free the bucket. */
			if (bucket->rr)
				SPF_dns_rr_free(bucket->rr);
			free(bucket);
			/* Set iterator back one step. */
			bucket = prev;	/* Might be NULL */
		}
	  	else if (rr->rr_type != rr_type) {
			/* Types differ */
		}
		else if (strcmp(rr->domain, domain) != 0) {
			/* Domains differ */
		}
		else {
			/* Move the bucket to the top of the chain. */
			if (prev != NULL) {
				prev->next = bucket->next;
				bucket->next = spfhook->cache[idx];
				spfhook->cache[idx] = bucket;
			}
			return bucket;
		}

		prev = bucket;		/* Might be NULL */
		if (bucket == NULL)	/* After an unlink */
			bucket = spfhook->cache[idx];
		else
			bucket = bucket->next;
	}

	return NULL;
}

/* This must be called with the lock held. */
static SPF_errcode_t
SPF_dns_cache_bucket_add(SPF_dns_cache_config_t *spfhook,
				SPF_dns_rr_t *rr, int idx)
{
	SPF_dns_cache_bucket_t	*bucket;

	bucket = (SPF_dns_cache_bucket_t *)
				malloc(sizeof(SPF_dns_cache_bucket_t));
	if (! bucket)
		return SPF_E_NO_MEMORY;
	bucket->next = spfhook->cache[idx];
	spfhook->cache[idx] = bucket;
	bucket->rr = rr;
	return SPF_E_SUCCESS;
}


/**
 * Patches up an rr for insertion into the cache.
 */
static SPF_errcode_t
SPF_dns_cache_rr_fixup(SPF_dns_cache_config_t *spfhook,
				SPF_dns_rr_t *cached_rr,
				const char *domain, ns_type rr_type)
{
    char			*p;

    /* make sure the RR has enough data to be useful for caching */
    if (cached_rr->rr_type == ns_t_any)
		cached_rr->rr_type = rr_type;

	/* XXX I'm still not sure about this bit. */
	if (cached_rr->domain == NULL || cached_rr->domain[0] != '\0') {
		char	*new_domain;
		size_t	 new_len = strlen(domain) + 1;

		if (cached_rr->domain_buf_len < new_len) {
			new_domain = realloc(cached_rr->domain, new_len);
			if (new_domain == NULL)
				return SPF_E_NO_MEMORY;
			cached_rr->domain = new_domain;
			cached_rr->domain_buf_len = new_len;
		}
		strcpy(cached_rr->domain, domain);
	}

    /* set up the ttl values */
    if ( cached_rr->ttl < spfhook->min_ttl )
		cached_rr->ttl = spfhook->min_ttl;

    if ( cached_rr->ttl < spfhook->txt_ttl
			&& cached_rr->rr_type == ns_t_txt || cached_rr->rr_type == ns_t_spf )
		cached_rr->ttl = spfhook->txt_ttl;

    if ( cached_rr->ttl < spfhook->err_ttl
			&& cached_rr->herrno != NETDB_SUCCESS )
		cached_rr->ttl = spfhook->err_ttl;

    if ( cached_rr->ttl < spfhook->rdns_ttl ) {
		p = strstr( cached_rr->domain, ".arpa" );
		if ( p && p[ sizeof( ".arpa" )-1 ] == '\0' )
			cached_rr->ttl = spfhook->rdns_ttl;
    }

	cached_rr->utc_ttl = cached_rr->ttl + time(NULL);

	return SPF_E_SUCCESS;
}


/**
 * Can return NULL on out-of-memory condition.
 */
static SPF_dns_rr_t *
SPF_dns_cache_lookup(SPF_dns_server_t *spf_dns_server,
				const char *domain, ns_type rr_type, int should_cache)
{
    SPF_dns_cache_config_t	*spfhook;
	SPF_dns_cache_bucket_t	*bucket;
	SPF_dns_rr_t			*cached_rr;
	SPF_dns_rr_t			*rr;
    int						 idx;

	spfhook = SPF_voidp2spfhook(spf_dns_server->hook);

	/* max_hash_len and cache_size are constant, so this be done
	 * outside the lock. */
	idx = hash(spfhook, domain, 0 /* spfhook->hash_mask+rr_type */);
	idx &= (spfhook->cache_size - 1);

    pthread_mutex_lock(&(spfhook->cache_lock));

	bucket = SPF_dns_cache_bucket_find(spfhook, domain, rr_type, idx);
	if (bucket != NULL) {
		if (bucket->rr != NULL) {
			if (SPF_dns_rr_dup(&rr, bucket->rr) == SPF_E_SUCCESS) {
				pthread_mutex_unlock(&(spfhook->cache_lock));
				return rr;
			}
			else if (rr != NULL) {
				SPF_dns_rr_free(rr);	/* Within the lock. :-( */
			}
		}
	}

	/* Make sure we don't hang onto this outside the lock.
	 * idx is presumably safe. */
	bucket = NULL;

	pthread_mutex_unlock(&(spfhook->cache_lock));

    if (!spf_dns_server->layer_below)
		return SPF_dns_rr_new_nxdomain(spf_dns_server, domain);

	rr = SPF_dns_lookup( spf_dns_server->layer_below,
					domain, rr_type, should_cache );
    if (spfhook->conserve_cache && !should_cache)
		return rr;

    pthread_mutex_lock(&(spfhook->cache_lock));

	if (SPF_dns_rr_dup(&cached_rr, rr) == SPF_E_SUCCESS) {
		if (SPF_dns_cache_rr_fixup(spfhook, cached_rr, domain, rr_type) == SPF_E_SUCCESS){
			if (SPF_dns_cache_bucket_add(spfhook, cached_rr, idx) == SPF_E_SUCCESS) {
				pthread_mutex_unlock(&(spfhook->cache_lock));
				return rr;
			}
		}
	}

    pthread_mutex_unlock(&(spfhook->cache_lock));

	if (cached_rr)
		SPF_dns_rr_free(cached_rr);

	return rr;

}


static void
SPF_dns_cache_free( SPF_dns_server_t *spf_dns_server )
{
    SPF_dns_cache_config_t	*spfhook;
	SPF_dns_cache_bucket_t	*bucket;
	SPF_dns_cache_bucket_t	*prev;
    int						 i;

	SPF_ASSERT_NOTNULL(spf_dns_server);

    spfhook = SPF_voidp2spfhook( spf_dns_server->hook );
	if ( spfhook ) {
		pthread_mutex_lock(&(spfhook->cache_lock));
	
		if (spfhook->cache) {
			for( i = 0; i < spfhook->cache_size; i++ ) {
				bucket = spfhook->cache[i];
				while (bucket != NULL) {
					prev = bucket;
					bucket = bucket->next;

					/* Free the bucket. */
					if (prev->rr)
						SPF_dns_rr_free(prev->rr);
					free(prev);
				}
			}
			free(spfhook->cache);
			spfhook->cache = NULL;
		}

		pthread_mutex_unlock(&(spfhook->cache_lock));

		/* 
		 * There is a risk that something might grab the mutex
		 * here and try to look things up and try to resolve
		 * stuff from a mashed cache it might happen but that's
		 * what you get for trying to simultaneously free and
		 * use a resource destroy will then return EBUSY but
		 * it'll probably segfault so there ain't much to be
		 * done really.
		 */
		pthread_mutex_destroy(&(spfhook->cache_lock));

		free(spfhook);
	}

    free(spf_dns_server);
}



SPF_dns_server_t *
SPF_dns_cache_new(SPF_dns_server_t *layer_below,
				const char *name, int debug, int cache_bits)
{
	SPF_dns_server_t		*spf_dns_server;
    SPF_dns_cache_config_t	*spfhook;

	SPF_ASSERT_NOTNULL(layer_below);

    if ( cache_bits < 1 || cache_bits > 16 )
		SPF_error( "cache bits out of range (1..16)." );


	spf_dns_server = malloc(sizeof(SPF_dns_server_t));
    if (spf_dns_server == NULL)
		return NULL;
	memset(spf_dns_server, 0, sizeof(SPF_dns_server_t));

    spf_dns_server->hook = malloc(sizeof(SPF_dns_cache_config_t));
    if (spf_dns_server->hook == NULL) {
		free(spf_dns_server);
		return NULL;
    }
	memset(spf_dns_server->hook, 0, sizeof(SPF_dns_cache_config_t));

	if (name == NULL)
		name = "cache";

    spf_dns_server->destroy     = SPF_dns_cache_free;
    spf_dns_server->lookup      = SPF_dns_cache_lookup;
    spf_dns_server->get_spf     = NULL;
    spf_dns_server->get_exp     = NULL;
    spf_dns_server->add_cache   = NULL;
    spf_dns_server->layer_below = layer_below;
    spf_dns_server->name        = name;
    spf_dns_server->debug       = debug;

    spfhook = SPF_voidp2spfhook( spf_dns_server->hook );

	spfhook->cache_size = 1 << cache_bits;
	spfhook->hash_mask  = spfhook->cache_size - 1;
	spfhook->max_hash_len = cache_bits > 4 ? cache_bits * 2 : 8;

    spfhook->cache = calloc(spfhook->cache_size,
									sizeof(*spfhook->cache));

#if 0
    spfhook->hit        = 0;
    spfhook->miss       = 0;
#endif

    spfhook->min_ttl    = 30;
    spfhook->err_ttl    = 30*60;
    spfhook->txt_ttl    = 30*60;
    spfhook->rdns_ttl   = 30*60;
    spfhook->conserve_cache  = cache_bits < 12;

    if (spfhook->cache == NULL) {
		free(spfhook);
		free(spf_dns_server);
		return NULL;
    }

	pthread_mutex_init(&(spfhook->cache_lock),NULL);

    return spf_dns_server;
}

void
SPF_dns_cache_set_ttl( SPF_dns_server_t *spf_dns_server,
				time_t min_ttl, time_t err_ttl,
				time_t txt_ttl, time_t rdns_ttl )
{
    SPF_dns_cache_config_t *spfhook;

	SPF_ASSERT_NOTNULL(spf_dns_server);

    spfhook = SPF_voidp2spfhook( spf_dns_server->hook );

    if (spfhook != NULL) {
        pthread_mutex_lock(&(spfhook->cache_lock));
        spfhook->min_ttl  = min_ttl;
        spfhook->err_ttl  = err_ttl;
        spfhook->txt_ttl  = txt_ttl;
        spfhook->rdns_ttl = rdns_ttl;
        pthread_mutex_unlock(&(spfhook->cache_lock));
    }
}


void
SPF_dns_set_conserve_cache( SPF_dns_server_t *spf_dns_server,
				int conserve_cache )
{
    SPF_dns_cache_config_t *spfhook;

	SPF_ASSERT_NOTNULL(spf_dns_server);

    spfhook = SPF_voidp2spfhook( spf_dns_server->hook );
	/* This is a boolean and it doesn't matter if it
	 * changes suddenly, thus no lock. */
    if (spfhook != NULL)
        spfhook->conserve_cache = conserve_cache;
}
