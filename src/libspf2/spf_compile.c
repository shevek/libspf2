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
#include "spf_internal.h"


#ifdef STDC_HEADERS
# include <stdio.h>		/* stdin / stdout */
# include <stdlib.h>	   /* malloc / free */
# include <ctype.h>		/* isupper / tolower */
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>	   /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>	   /* strstr / strdup */
# endif
#endif



#undef SPF_ALLOW_DEPRECATED_DEFAULT

#include "spf.h"
#include "spf_internal.h"
#include "spf_response.h"
#include "spf_record.h"

typedef
enum SPF_cidr_enum {
	CIDR_NONE, CIDR_OPTIONAL, CIDR_ONLY
} SPF_cidr_t;

typedef
enum SPF_domspec_enum {
	DOMSPEC_NONE, DOMSPEC_OPTIONAL, DOMSPEC_REQUIRED
} SPF_domspec_t;

/**
 * This is greater than any possible total mechanism or modifier.
 *	 SPF_MAX_MOD_LEN  + SPF_MAX_STR_LEN
 *	 SPF_MAX_MECH_LEN + SPF_MAX_STR_LEN
 */
#define SPF_RECORD_BUFSIZ	  4096

#define ALIGN_DECL(decl) union { double d; long l; decl } __attribute__((aligned(_ALIGN_SZ))) u
#define ALIGNED_DECL(var) u.var



typedef
struct SPF_mechtype_struct
{
	unsigned char		 mech_type;
	unsigned char		 is_dns_mech;
	SPF_domspec_t		 has_domainspec;
	SPF_cidr_t			 has_cidr;
} SPF_mechtype_t;

static const SPF_mechtype_t spf_mechtypes[] = {
	{ MECH_UNKNOWN,		FALSE,		DOMSPEC_NONE,		CIDR_NONE },
	{ MECH_A,			TRUE,		DOMSPEC_OPTIONAL,	CIDR_OPTIONAL },
	{ MECH_MX,			TRUE,		DOMSPEC_OPTIONAL,	CIDR_OPTIONAL },
	{ MECH_PTR,			TRUE,		DOMSPEC_OPTIONAL,	CIDR_NONE },
	{ MECH_INCLUDE,		TRUE,		DOMSPEC_REQUIRED,	CIDR_NONE },
	{ MECH_IP4,			FALSE,		DOMSPEC_REQUIRED,	CIDR_OPTIONAL },
	{ MECH_IP6,			FALSE,		DOMSPEC_REQUIRED,	CIDR_OPTIONAL },
	{ MECH_EXISTS,		TRUE,		DOMSPEC_REQUIRED,	CIDR_NONE },
	{ MECH_ALL,			FALSE,		DOMSPEC_NONE,		CIDR_NONE },
	{ MECH_REDIRECT,	TRUE,		DOMSPEC_REQUIRED,	CIDR_NONE },
};

#define spf_num_mechanisms \
		sizeof(spf_mechtypes) / sizeof(spf_mechtypes[0])

static const SPF_mechtype_t *
SPF_mechtype_find(int mech_type)
{
	size_t		 i;
	for (i = 0; i < spf_num_mechanisms; i++) {
		if (spf_mechtypes[i].mech_type == mech_type)
			return &spf_mechtypes[i];
	}
	return NULL;
}

__attribute__((warn_unused_result))
static int
SPF_c_ensure_capacity(void **datap, size_t *sizep, size_t length)
{
	size_t		 size = *sizep;
	if (length > size)
		size = length + (length / 4);
	if (size > *sizep) {
		void	*tmp = realloc(*datap, size);
		if (!tmp)
			return -1;
		// memset(tmp + *sizep, 'C', (size - *sizep));
		*datap = tmp;
		*sizep = size;
	}
	return 0;
}

/**
 * Parses an ip6 CIDR.
 *
 * Called with src pointing to the '/'.
 *
 * If a struct for IP addresses is added which itself contains a
 * CIDR field, then this must be modified to take a (cidr *) rather
 * than a (SPF_data_cidr_t *)
 */
static SPF_errcode_t
SPF_c_parse_cidr_ip6(SPF_response_t *spf_response,
				unsigned char *maskp,
				const char *src)
{
	int		 mask;

	/*
	if (spf_server->debug > 2)
		SPF_debugf("Parsing ip6 CIDR starting at %s", src);
	*/

	mask = strtoul(src + 1, NULL, 10);

	if (mask > 128) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, src,
						"Invalid IPv6 CIDR netmask (>128)");
	}
	else if (mask == 0) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, src,
						"Invalid IPv6 CIDR netmask (=0)");
	}
	else if (mask == 128) {
		mask = 0;
	}

	*maskp = mask;

	return SPF_E_SUCCESS;
}

/**
 * Parses an ip4 CIDR.
 *
 * Called with src pointing to the '/', the second '/' if we are in
 * a '//' notation, so that the digits start at src + 1.
 *
 * SPF_c_parse_cidr relies on the behaviour of strtoul terminating
 * on a '/' as well as a nul byte here.
 */
static SPF_errcode_t
SPF_c_parse_cidr_ip4(SPF_response_t *spf_response,
				unsigned char *maskp,
				const char *src)
{
	int		 mask;

	/*
	if (spf_server->debug > 2)
		SPF_debugf("Parsing ip4 CIDR starting at %s", src);
	*/

	mask = strtoul(src + 1, NULL, 10);

	if ( mask > 32 ) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, src,
						"Invalid IPv4 CIDR netmask (>32)");
	}
	else if ( mask == 0 ) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, src,
						"Invalid IPv4 CIDR netmask (=0)");
	}
	else if ( mask == 32 ) {
		mask = 0;
	}

	*maskp = mask;

	return SPF_E_SUCCESS;
}

/**
 * Parses an SPF CIDR.
 *
 * Modifies *src_len if a CIDR is found.
 */
static SPF_errcode_t
SPF_c_parse_cidr(SPF_response_t *spf_response,
				SPF_data_cidr_t *data,
				const char *src, size_t *src_len)
{
	SPF_errcode_t	 err;
	size_t			 idx;

	memset(data, 0, sizeof(SPF_data_cidr_t));
	data->parm_type = PARM_CIDR;

	/* Find the beginning of the CIDR length notation.
	 * XXX This assumes that there is a non-digit in the string.
	 * This is always true for SPF records with domainspecs, since
	 * there has to be an = or a : before it. */
	idx = *src_len - 1;
	while (idx > 0 && isdigit( (unsigned char)(src[idx]) ))
		idx--;

	/* Something is frying my brain and I can't pull an invariant
	 * out of this suitable for resetting *endp. So I nested the
	 * 'if's instead. Perhaps I'll manage to refactor later. */

	/* If we have a slash which isn't the last character. */
	if (idx < (*src_len - 1) && src[idx] == '/') {
		if (idx > 0 && src[idx - 1] == '/') {
			/* get IPv6 CIDR length */
			err = SPF_c_parse_cidr_ip6(spf_response, &data->ipv6, &src[idx]);
			if (err)
				return err;
			/* now back up and see if there is a ipv4 cidr length */
			*src_len = idx - 1;	/* The index of the first '/' */
			idx = *src_len - 1;	/* Last character of what is before. */
			while (idx > 0 && isdigit( (unsigned char)(src[idx]) ))
				idx--;

			/* get IPv4 CIDR length */
			if (idx < (*src_len - 1) && src[idx] == '/') {
				/* - we know that strtoul terminates on the
				 * '/' so we don't need to null-terminate the
				 * input string. */
				err = SPF_c_parse_cidr_ip4(spf_response, &data->ipv4, &src[idx]);
				if (err)
					return err;
				*src_len = idx;
			}
		}
		else {
			/* get IPv4 CIDR length */
			err = SPF_c_parse_cidr_ip4(spf_response, &data->ipv4, &src[idx]);
			if (err)
				return err;
			*src_len = idx;
		}
	}

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_c_parse_var(SPF_response_t *spf_response, SPF_data_var_t *data,
				const char *src, int is_mod)
{
	const char		*token;
	const char		*p;
	char			 c;
	int				 val;

	memset(data, 0, sizeof(SPF_data_var_t));

	p = src;

	/* URL encoding */
	c = *p;
	if ( isupper( (unsigned char)( c ) ) )
	{
		data->url_encode = TRUE;
		c = tolower(c);
	}
	else
		data->url_encode = FALSE;

#define SPF_CHECK_IN_MODIFIER() \
		if ( !is_mod ) \
			return SPF_response_add_error_ptr(spf_response, \
						SPF_E_INVALID_VAR, NULL, p, \
						"'%c' macro is only valid in modifiers", c);

	switch ( c )
	{
	case 'l':				/* local-part of envelope-sender */
		data->parm_type = PARM_LP_FROM;
		break;

	case 's':				/* envelope-sender				*/
		data->parm_type = PARM_ENV_FROM;
		break;

	case 'o':				/* envelope-domain				*/
		data->parm_type = PARM_DP_FROM;
		break;

	case 'd':				/* current-domain				*/
		data->parm_type = PARM_CUR_DOM;
		break;

	case 'i':				/* SMTP client IP				*/
		data->parm_type = PARM_CLIENT_IP;
		break;

	case 'c':				/* SMTP client IP (pretty)		*/
		SPF_CHECK_IN_MODIFIER();
		data->parm_type = PARM_CLIENT_IP_P;
		break;

	case 't':				/* time in UTC epoch secs		*/
		SPF_CHECK_IN_MODIFIER();
		data->parm_type = PARM_TIME;
		break;

	case 'p':				/* SMTP client domain name		*/
		data->parm_type = PARM_CLIENT_DOM;
		break;

	case 'v':				/* IP ver str - in-addr/ip6		*/
		data->parm_type = PARM_CLIENT_VER;
		break;

	case 'h':				/* HELO/EHLO domain				*/
		data->parm_type = PARM_HELO_DOM;
		break;

	case 'r':				/* receiving domain				*/
		SPF_CHECK_IN_MODIFIER();
		data->parm_type = PARM_REC_DOM;
		break;

	default:
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_VAR,
						NULL, p,
						"Unknown variable '%c'", c);
	}
	p++;
	token = p;
		
	/* get the number of subdomains to truncate to */
	val = 0;
	while ( isdigit( (unsigned char)( *p ) ) )
	{
		val *= 10;
		val += *p - '0';
		p++;
	}
	if ( val > 128  ||  (val <= 0 && p != token) )
		return SPF_response_add_error_ptr(spf_response, SPF_E_BIG_SUBDOM,
						NULL, token,
						"Subdomain truncation depth too large");
	data->num_rhs = val;
	token = p;
		
	/* should the string be reversed? */
	if ( *p == 'r' )
	{
		data->rev = 1;
		p++;
	}
	else
		data->rev = FALSE;
	token = p;


	/* check for delimiters */
	data->delim_dot = FALSE;
	data->delim_dash = FALSE;
	data->delim_plus = FALSE;
	data->delim_equal = FALSE;
	data->delim_bar = FALSE;
	data->delim_under = FALSE;

	/*vi:{*/
	if ( *p == '}' )
		data->delim_dot = TRUE;

	/*vi:{*/
	while( *p != '}' )
	{
		token = p;
		switch( *p )
		{
		case '.':
			data->delim_dot = TRUE;
			break;
				
		case '-':
			data->delim_dash = TRUE;
			break;
				
		case '+':
			data->delim_plus = TRUE;
			break;
				
		case '=':
			data->delim_equal = TRUE;
			break;
				
		case '|':
			data->delim_bar = TRUE;
			break;
				
		case '_':
			data->delim_under = TRUE;
			break;

		default:
			return SPF_response_add_error_ptr(spf_response,
							SPF_E_INVALID_DELIM, NULL, p,
							"Invalid delimiter '%c'", *p);
		}
		p++;
	}
	p++;
	token = p;


	return SPF_E_SUCCESS;
}


		/* Sorry, Wayne. */
#define SPF_ADD_LEN_TO(_val, _len, _max) do { \
			if ( (_val) + _align_sz(_len) > (_max) ) {				\
				return SPF_response_add_error_ptr(spf_response,		\
					big_err, NULL, src,								\
					"SPF domainspec too long "						\
					"(%d chars, %d max)",							\
					(_val) + (_len), _max);							\
			}														\
			(_val) += _align_sz(_len);								\
		} while(0)

#define SPF_INIT_STRING_LITERAL(_avail)	do { \
			data->ds.parm_type = PARM_STRING;						\
			data->ds.len = 0;										\
			/* Magic numbers for x/Nc in gdb. */					\
			data->ds.__unused0 = 0xba; data->ds.__unused1 = 0xbe;	\
			dst = SPF_data_str( data );								\
			ds_avail = _avail;										\
			ds_len = 0;												\
		} while(0)

#define SPF_ENSURE_STRING_AVAIL(_len)	do {		\
			if (ds_len + _len > ds_avail)			\
				return SPF_response_add_error_ptr(spf_response,	\
								SPF_E_BIG_STRING, NULL, src,	\
							"String literal fragment too long "	\
							"(%d chars, %d max)",				\
							ds_len, ds_avail);					\
		} while(0)

#define SPF_FINI_STRING_LITERAL()		do { \
			if ( ds_len > 0 ) {										\
				if ( ds_len > SPF_MAX_STR_LEN ) {					\
					return SPF_response_add_error_ptr(spf_response,		\
									SPF_E_BIG_STRING, NULL, src,	\
								"String literal too long "			\
								"(%d chars, %d max)",				\
								ds_len, SPF_MAX_STR_LEN);			\
				}													\
				data->ds.len = ds_len;								\
				len = sizeof( *data ) + ds_len;						\
				SPF_ADD_LEN_TO(*data_used, len, data_avail);		\
				data = SPF_data_next( data );						\
				ds_len = 0;											\
			}														\
		} while(0)

/**
 * Parses an SPF macro string.
 *
 * Note that we cannot write data_avail bytes from data, since we
 * might be called with a modified data pointer. We MUST compare
 * data_used with data_avail.
 *
 * @param spf_server The SPF server on whose behalf the record is being compiled.
 * @param spf_response The SPF response in which to store errors.
 * @param data Output buffer pointer.
 * @param data_used Output parameter for amount of data written to output buffer.
 * @param data_avail Input parameter for size of output buffer.
 * @param src Input buffer pointer.
 * @param src_len Input buffer length.
 * @param big_err The error code to return on an over-length condition.
 * @param is_mod True if this is a modifier.
 */
static SPF_errcode_t
SPF_c_parse_macro(SPF_server_t *spf_server,
				SPF_response_t *spf_response,
				SPF_data_t *data, size_t *data_used, size_t data_avail,
				const char *src, size_t src_len,
				SPF_errcode_t big_err,
				int is_mod)
{
	SPF_errcode_t		 err;
			/* Generic parsing iterators and boundaries */
	size_t				 idx;
	size_t				 len;
			/* For parsing strings. */
	char				*dst;
	size_t				 ds_avail;
	size_t				 ds_len;

	if (spf_server->debug)
		SPF_debugf("Parsing macro starting at %s", src);

#if 0
	if ((void *)data != _align_ptr((void *)data))
		SPF_errorf("Data pointer %p is not aligned: Cannot compile.",
		data);
#endif

	/*
	 * Create the data blocks
	 */
	idx = 0;

	/* Initialise the block as a string. If ds_len == 0 later, we
	 * will just clobber it. */
	SPF_INIT_STRING_LITERAL(data_avail - *data_used);

	// while ( p != end ) {
	while (idx < src_len) {
		if (spf_server->debug > 3)
			SPF_debugf("Current data is at %p", data);
		/* Either the unit is terminated by a space, or we hit a %.
		 * We should only hit a space if we run past src_len. */
		len = strcspn(&src[idx], " %");	// XXX Also tab?
		if (len > 0) {				/* An optimisation */
			/* Don't over-run into the CIDR. */
			if (idx + len > src_len)
				len = src_len - idx;
			if (spf_server->debug > 3)
				SPF_debugf("Adding string literal (%lu): '%*.*s'",
								(unsigned long)len,
								(int)len, (int)len, &src[idx]);
			/* XXX Bounds-check here. */
			SPF_ENSURE_STRING_AVAIL(len);
			memcpy(dst, &src[idx], len);
			ds_len += len;
			dst += len;
			idx += len;

			/* If len == 0 then we never entered the while(). Thus
			 * if idx == src_len, then len != 0 and we reach this test.
			 */
		}
		/* However, this logic is overcomplex and I am a simpleton,
		 * so I have moved it out of the condition above. */
		if (idx == src_len)
			break;

		/* Now, we must have a %-escape code, since if we hit a
		 * space, then we are at the end.
		 * Incrementing idx consumes the % we hit first, and then
		 * we switch on the following character, which also
		 * increments idx. */
		idx++;
		switch (src[idx]) {
		case '%':
			if (spf_server->debug > 3)
				SPF_debugf("Adding literal %%");
			SPF_ENSURE_STRING_AVAIL(1);
			*dst++ = '%';
			ds_len++;
			idx++;
			break;
			
		case '_':
			if (spf_server->debug > 3)
				SPF_debugf("Adding literal space");
			SPF_ENSURE_STRING_AVAIL(1);
			*dst++ = ' ';
			ds_len++;
			idx++;
			break;

		case '-':
			if (spf_server->debug > 3)
				SPF_debugf("Adding escaped space");
			SPF_ENSURE_STRING_AVAIL(3);
			*dst++ = '%'; *dst++ = '2'; *dst++ = '0';
			ds_len += 3;
			idx++;
			break;

		default:
			if (spf_server->debug > 3)
				SPF_debugf("Adding illegal %%-follower '%c' at %d",
				src[idx], idx);
			/* SPF spec says to treat it as a literal, not
			 * SPF_E_INVALID_ESC */
			/* FIXME   issue a warning? */
			SPF_ENSURE_STRING_AVAIL(1);
			*dst++ = '%';
			ds_len++;
			break;

		case '{':  /*vi:}*/
			SPF_FINI_STRING_LITERAL();
			if (spf_server->debug > 3)
				SPF_debugf("Adding macro, data is at %p", data);

			/* this must be a variable */
			idx++;
			err = SPF_c_parse_var(spf_response, &data->dv, &src[idx], is_mod);
			if (err != SPF_E_SUCCESS)
				return err;
			idx += strcspn(&src[idx], "} ");
			if (src[idx] == '}')
				idx++;
			else if (src[idx] == ' ')
				return SPF_response_add_error_ptr(spf_response,
						SPF_E_INVALID_VAR,
						src, &src[idx],
						"Unterminated variable?");


			len = SPF_data_len(data);
			SPF_ADD_LEN_TO(*data_used, len, data_avail);
			data = SPF_data_next( data );
			if (spf_server->debug > 3)
				SPF_debugf("Next data is at %p", data);

			SPF_INIT_STRING_LITERAL(data_avail - *data_used);

			break;
		}
	}

	SPF_FINI_STRING_LITERAL();

	return SPF_E_SUCCESS;

}

/* What a fuck-ugly prototype. */
/**
 * Parses an SPF domainspec.
 *
 * @param spf_server The SPF server on whose behalf the record is being compiled.
 * @param spf_response The SPF response in which to store errors.
 * @param data Output buffer pointer.
 * @param data_used Output parameter for amount of data written to output buffer.
 * @param data_avail Input parameter for size of output buffer.
 * @param src Input buffer pointer.
 * @param src_len Input buffer length.
 * @param big_err The error code to return on an over-length condition.
 * @param cidr_ok True if a CIDR mask is permitted on this domainspec.
 * @param is_mod True if this is a modifier.
 */
static SPF_errcode_t
SPF_c_parse_domainspec(SPF_server_t *spf_server,
				SPF_response_t *spf_response,
				SPF_data_t *data, size_t *data_used, size_t data_avail,
				const char *src, size_t src_len,
				SPF_errcode_t big_err,
				SPF_cidr_t cidr_ok, int is_mod)
{
	SPF_errcode_t		 err;
			/* Generic parsing iterators and boundaries */
	size_t				len;

	if (spf_server->debug)
		SPF_debugf("Parsing domainspec starting at %s, cidr is %s",
						src,
						cidr_ok == CIDR_OPTIONAL ? "optional" :
						cidr_ok == CIDR_ONLY ? "only" :
						cidr_ok == CIDR_NONE ? "forbidden" :
						"ERROR!"
						);

	/*
	 * create the CIDR length info
	 */
	if (cidr_ok == CIDR_OPTIONAL || cidr_ok == CIDR_ONLY) {
		err = SPF_c_parse_cidr(spf_response, &data->dc, src, &src_len);
		if (err != SPF_E_SUCCESS)
			return err;
		if (data->dc.ipv4 != 0  ||  data->dc.ipv6 != 0) {
			len = SPF_data_len(data);
			SPF_ADD_LEN_TO(*data_used, len, data_avail);
			data = SPF_data_next(data);
		}

		if (cidr_ok == CIDR_ONLY && src_len > 0) {
			/* We had a mechanism followed by a '/', thus it HAS to be
			 * a CIDR, and the peculiar-looking error message is
			 * justified. However, we don't know _which_ CIDR. */
			return SPF_response_add_error_ptr(spf_response,
							SPF_E_INVALID_CIDR,
							NULL, src,
							"Invalid CIDR after mechanism");
		}
	}

	return SPF_c_parse_macro(spf_server, spf_response,
			data, data_used, data_avail,
			src, src_len, big_err, is_mod);
}


/**
 * Parses the data for an ip4 mechanism.
 *
 * When this method is called, start points to the ':'.
 */
static SPF_errcode_t
SPF_c_parse_ip4(SPF_response_t *spf_response, SPF_mech_t *mech, char const *start)
{
	const char			*end;
	const char			*p;

	char				 buf[ INET6_ADDRSTRLEN ];
	size_t				 len;
	SPF_errcode_t		 err;

	unsigned char		 mask;
	struct in_addr		*addr;

	start++;
	len = strcspn(start, " ");
	end = start + len;
	p = end - 1;

	mask = 0;
	while (isdigit( (unsigned char)(*p) ))
		p--;
	if (p != (end - 1) && *p == '/') {
		err = SPF_c_parse_cidr_ip4(spf_response, &mask, p);
		if (err)
			return err;
		end = p;
	}
	mech->mech_len = mask;

	len = end - start;
	if ( len > sizeof( buf ) - 1 )
		return SPF_E_INVALID_IP4;

	memcpy( buf, start, len );
	buf[ len ] = '\0';
	addr = SPF_mech_ip4_data(mech);
	err = inet_pton( AF_INET, buf, addr );
	if ( err <= 0 )
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_IP4,
						NULL, buf, NULL);

	return SPF_E_SUCCESS;
}

/**
 * Parses the data for an ip6 mechanism.
 *
 * When this method is called, start points to the ':'.
 */
static SPF_errcode_t
SPF_c_parse_ip6(SPF_response_t *spf_response, SPF_mech_t *mech, char const *start)
{
	const char			*end;
	const char			*p;

	char				 buf[ INET6_ADDRSTRLEN ];
	size_t				 len;
	int					 err;

	unsigned char		 mask;
	struct in6_addr		*addr;

	start++;
	len = strcspn(start, " ");
	end = start + len;
	p = end - 1;

	mask = 0;
	while (isdigit( (unsigned char)(*p) ))
		p--;
	if (p != (end - 1) && *p == '/') {
		err = SPF_c_parse_cidr_ip6(spf_response, &mask, p);
		if (err)
			return err;
		end = p;
	}
	mech->mech_len = mask;

	len = end - start;
	if ( len > sizeof( buf ) - 1 )
		return SPF_E_INVALID_IP6;

	memcpy( buf, start, len );
	buf[ len ] = '\0';
	addr = SPF_mech_ip6_data(mech);
	err = inet_pton( AF_INET6, buf, addr );
	if ( err <= 0 )
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_IP6,
						NULL, buf, NULL);

	return SPF_E_SUCCESS;
}


/* XXX TODO: Make this take (const char *) instead of (const char **)
 * because the caller ignores the modified value. */
__attribute__((warn_unused_result))
static SPF_errcode_t
SPF_c_mech_add(SPF_server_t *spf_server,
				SPF_record_t *spf_record, SPF_response_t *spf_response,
				const SPF_mechtype_t *mechtype, int prefix,
				const char **mech_value)
{
	/* If this buffer is an irregular size, intel gcc does not align
	 * it properly, and all hell breaks loose. */
ALIGN_DECL(
	char				 buf[SPF_RECORD_BUFSIZ];
);
	SPF_mech_t			*spf_mechanism = (SPF_mech_t *)ALIGNED_DECL(buf);
	SPF_data_t			*data;
	size_t				 data_len;
	size_t				 len;
	size_t				 src_len;

	SPF_errcode_t		 err;

	memset(u.buf, 'B', sizeof(u.buf));	/* Poison the buffer. */
	memset(spf_mechanism, 0, sizeof(SPF_mech_t));

	if (spf_server->debug)
		SPF_debugf("SPF_c_mech_add: type=%d, value=%s",
						mechtype->mech_type, *mech_value);

	spf_mechanism->prefix_type = prefix;
	spf_mechanism->mech_type = mechtype->mech_type;
	spf_mechanism->mech_len = 0;

	len = sizeof( SPF_mech_t );

	if ( spf_record->mech_len + len > SPF_MAX_MECH_LEN )
		return SPF_E_BIG_MECH;

	data = SPF_mech_data(spf_mechanism);
	data_len = 0;

	src_len = strcspn(*mech_value, " ");

	switch (mechtype->mech_type) {
		/* We know the properties of IP4 and IP6. */
			case MECH_IP4:
			if (**mech_value == ':') {
				err = SPF_c_parse_ip4(spf_response, spf_mechanism, *mech_value);
				data_len = sizeof(struct in_addr);
			}
			else {
				err = SPF_E_MISSING_OPT;
				SPF_response_add_error_ptr(spf_response, err,
						NULL, *mech_value,
						"Mechanism requires a value.");
			}
			break;

		case MECH_IP6:
			if (**mech_value == ':') {
				err = SPF_c_parse_ip6(spf_response, spf_mechanism, *mech_value);
				data_len = sizeof(struct in6_addr);
			}
			else {
				err = SPF_E_MISSING_OPT;
				SPF_response_add_error_ptr(spf_response, err,
						NULL, *mech_value,
						"Mechanism requires a value.");
			}
			break;

		default:
			if (**mech_value == ':' || **mech_value == '=') {
				if (mechtype->has_domainspec == DOMSPEC_NONE) {
					err = SPF_E_INVALID_OPT;
					SPF_response_add_error_ptr(spf_response, err,
							NULL, *mech_value,
							"Mechanism does not permit a value.");
				}
				else {
					(*mech_value)++; src_len--;
					err = SPF_c_parse_domainspec(spf_server,
									spf_response,
									data, &data_len, SPF_MAX_MECH_LEN,
									*mech_value, src_len,
									SPF_E_BIG_MECH,
									mechtype->has_cidr, FALSE);
				}
			}
			else if (**mech_value == '/') {
				if (mechtype->has_domainspec == DOMSPEC_REQUIRED) {
					err = SPF_E_MISSING_OPT;
					SPF_response_add_error_ptr(spf_response, err,
							NULL, *mech_value,
							"Mechanism requires a value.");
				}
				else if (mechtype->has_cidr == CIDR_NONE) {
					err = SPF_E_INVALID_CIDR;
					SPF_response_add_error_ptr(spf_response, err,
							NULL, *mech_value,
							"Mechanism does not permit a CIDR.");
				}
				else {
					err = SPF_c_parse_domainspec(spf_server,
									spf_response,
									data, &data_len, SPF_MAX_MECH_LEN,
									*mech_value, src_len,
									SPF_E_BIG_MECH,
									CIDR_ONLY, FALSE);
				}
			}
			else if (**mech_value == ' '  ||  **mech_value == '\0') {
				if (mechtype->has_domainspec == DOMSPEC_REQUIRED) {
					err = SPF_E_MISSING_OPT;
					SPF_response_add_error_ptr(spf_response, err,
							NULL, *mech_value,
							"Mechanism requires a value.");
				}
				else {
					err = SPF_E_SUCCESS;
				}
			}
			else {
				err = SPF_E_SYNTAX;
				SPF_response_add_error_ptr(spf_response, err,
						NULL, *mech_value,
						"Unknown character '%c' after mechanism.",
						**mech_value);
			}

			/* Does not apply to ip4/ip6 */
			spf_mechanism->mech_len = data_len;
			break;
	}

	len += data_len;

	/* Copy the thing in. */
	if (err == SPF_E_SUCCESS) {
		if (mechtype->is_dns_mech)
			spf_record->num_dns_mech++;
		if (SPF_c_ensure_capacity((void **)&spf_record->mech_first,
							&spf_record->mech_size,
							spf_record->mech_len + len) < 0)
			return SPF_response_add_error_ptr(spf_response,
							SPF_E_NO_MEMORY,
							NULL, NULL,
							"Failed to allocate memory for mechanism");
		memcpy( (char *)spf_record->mech_first + spf_record->mech_len,
			spf_mechanism,
			len);
		spf_record->mech_len += len;
		spf_record->num_mech++;
	}

	*mech_value += src_len;

	return err;
}

__attribute__((warn_unused_result))
static SPF_errcode_t
SPF_c_mod_add(SPF_server_t *spf_server,
				SPF_record_t *spf_record, SPF_response_t *spf_response,
				const char *mod_name, size_t name_len,
				const char **mod_value)
{
	/* If this buffer is an irregular size, intel gcc does not align
	 * it properly, and all hell breaks loose. */
ALIGN_DECL(
	char				 buf[SPF_RECORD_BUFSIZ];
);
	SPF_mod_t			*spf_modifier = (SPF_mod_t *)u.buf;
	SPF_data_t			*data;
	size_t				 data_len;
	size_t				 len;
	size_t				 src_len;

	SPF_errcode_t		 err;

	if (spf_server->debug)
		SPF_debugf("Adding modifier name=%lu@%s, value=%s",
						(unsigned long)name_len, mod_name, *mod_value);

	memset(u.buf, 'A', sizeof(u.buf));
	memset(spf_modifier, 0, sizeof(SPF_mod_t));

	if ( name_len > SPF_MAX_MOD_LEN )
		return SPF_E_BIG_MOD;

	spf_modifier->name_len = name_len;
	spf_modifier->data_len = 0;

	/* So that spf_modifier + len == SPF_mod_data(spf_modifier) */
	len = _align_sz(sizeof( SPF_mod_t ) + name_len);

	if ( spf_record->mod_len + len > SPF_MAX_MOD_LEN )
		return SPF_E_BIG_MOD;

	memcpy(SPF_mod_name(spf_modifier), mod_name, name_len);

	data = SPF_mod_data(spf_modifier);
	data_len = 0;

	src_len = strcspn(*mod_value, " ");

	err = SPF_c_parse_macro(spf_server,
					spf_response,
					data, &data_len, SPF_MAX_MOD_LEN,
					*mod_value, src_len,
					SPF_E_BIG_MOD,
					TRUE );
	spf_modifier->data_len = data_len;
	len += data_len;

	/* Copy the thing in. */
	if (err == SPF_E_SUCCESS) {
		if (SPF_c_ensure_capacity((void **)&spf_record->mod_first,
							&spf_record->mod_size,
							spf_record->mod_len + len) < 0)
			return SPF_response_add_error_ptr(spf_response,
							SPF_E_NO_MEMORY,
							NULL, NULL,
							"Failed to allocate memory for modifier");
		memcpy( (char *)spf_record->mod_first + spf_record->mod_len,
			spf_modifier,
			len);
		spf_record->mod_len += len;
		spf_record->num_mod++;
	}

	return err;
}

static void
SPF_record_lint(SPF_server_t *spf_server,
								SPF_response_t *spf_response,
								SPF_record_t *spf_record)
{
	SPF_data_t		*d, *data_end;

	char		*s;
	char		*s_end;

	int			 found_non_ip;
	int			 found_valid_tld;
	
	SPF_mech_t  *mech;
	SPF_data_t  *data;
	
	int				i;

	/* FIXME  these warnings suck.  Should call SPF_id2str to give more
	 * context. */

	mech = spf_record->mech_first;
	for (i = 0;
					i < spf_record->num_mech;
						i++,
						mech = SPF_mech_next( mech ) )
	{
		if ( ( mech->mech_type == MECH_ALL
			   || mech->mech_type == MECH_REDIRECT )
			 && i != spf_record->num_mech - 1 )
		{
			SPF_response_add_warn(spf_response, SPF_E_MECH_AFTER_ALL,
							"Mechanisms found after the \"all:\" "
							"mechanism will be ignored.");
		}

		/*
		 * if we are dealing with a mechanism, make sure that the data
		 * at least looks like a valid host name.
		 *
		 * note: this routine isn't called to handle ip4: and ip6: and all
		 * the other mechanisms require a host name.
		 */

		if ( mech->mech_type == MECH_IP4
			 || mech->mech_type == MECH_IP6 )
			continue;

		data = SPF_mech_data( mech );
		data_end = SPF_mech_end_data( mech );
		if ( data == data_end )
			continue;

		if ( data->dc.parm_type == PARM_CIDR )
		{
			data = SPF_data_next( data );
			if ( data == data_end )
				continue;
		}
		

		found_valid_tld = FALSE;
		found_non_ip = FALSE;

		for( d = data; d < data_end; d = SPF_data_next( d ) )
		{
			switch( d->dv.parm_type )
			{
			case PARM_CIDR:
				SPF_error( "Multiple CIDR parameters found" );
				break;
				
			case PARM_CLIENT_IP:
			case PARM_CLIENT_IP_P:
			case PARM_LP_FROM:
				found_valid_tld = FALSE;
				break;

			case PARM_STRING:
				found_valid_tld = FALSE;

				s = SPF_data_str( d );
				s_end = s + d->ds.len;
				for( ; s < s_end; s++ ) {
					if ( !isdigit( (unsigned char)( *s ) ) && *s != '.' && *s != ':' )
						found_non_ip = TRUE;

					if ( *s == '.' ) 
						found_valid_tld = TRUE;
					else if ( !isalpha( (unsigned char)( *s ) ) )
						found_valid_tld = FALSE;
				}
				break;

			default:
				found_non_ip = TRUE;
				found_valid_tld = TRUE;
			
				break;
			}
		}

		if ( !found_valid_tld || !found_non_ip ) {
			if ( !found_non_ip )
				SPF_response_add_warn(spf_response, SPF_E_BAD_HOST_IP,
							"Invalid hostname (an IP address?)");
			else if ( !found_valid_tld )
				SPF_response_add_warn(spf_response, SPF_E_BAD_HOST_TLD,
							"Hostname has a missing or invalid TLD");
		}

	}

	/* FIXME check for modifiers that should probably be mechanisms */
}



/**
 * The SPF compiler.
 *
 * It converts the SPF record in string format that is easy for people
 * to deal with into a compact binary format that is easy for
 * computers to deal with.
 */
SPF_errcode_t
SPF_record_compile(SPF_server_t *spf_server,
								SPF_response_t *spf_response, 
								SPF_record_t **spf_recordp,
								const char *record)
{
	const SPF_mechtype_t*mechtype;
	SPF_record_t		*spf_record;
	SPF_error_t			*spf_error;
	SPF_errcode_t		 err;
	
	const char			*name_start;
	size_t				 name_len;

	const char			*val_start;
	const char			*val_end;
	
	int					 prefix;

	const char			*p;
	int					 i;


	/*
	 * make sure we were passed valid data to work with
	 */
	SPF_ASSERT_NOTNULL(spf_server);
	SPF_ASSERT_NOTNULL(spf_recordp);
	SPF_ASSERT_NOTNULL(record);

	if (spf_server->debug)
		SPF_debugf("Compiling record %s", record);

	/*
	 * and make sure that we will always set *spf_recordp
	 * just incase we can't find a valid SPF record
	 */
	*spf_recordp = NULL;

	/*
	 * See if this is record is even an SPF record
	 */
	p = record;

	if (strncasecmp(p, SPF_VER_STR, sizeof(SPF_VER_STR) - 1) != 0)
		return SPF_response_add_error_ptr(spf_response, SPF_E_NOT_SPF,
						NULL, p,
						"Could not find a valid SPF record");
	p += sizeof( SPF_VER_STR ) - 1;

	if ( *p != '\0' && *p != ' ' )
		return SPF_response_add_error_ptr(spf_response, SPF_E_NOT_SPF,
						NULL, p,
						"Could not find a valid SPF record");

	spf_record = SPF_record_new(spf_server, record);
	if (spf_record == NULL) {
		*spf_recordp = NULL;
		return SPF_response_add_error_ptr(spf_response, SPF_E_NO_MEMORY,
						NULL, p,
						"Failed to allocate an SPF record");
	}
	spf_record->version = 1;
	*spf_recordp = spf_record;

	/*
	 * parse the SPF record
	 */
	while (*p != '\0') {
		/* TODO WARN: If it's a \n or a \t */
		/* skip to the next token */
		while (*p == ' ')
			p++;

		if (*p == '\0')
			break;

		/* see if we have a valid prefix */
		prefix = PREFIX_UNKNOWN;
		switch (*p) {
			case '+':
				prefix = PREFIX_PASS;
				p++;
				break;
				
			case '-':
				prefix = PREFIX_FAIL;
				p++;
				break;
				
			case '~':
				prefix = PREFIX_SOFTFAIL;
				p++;
				break;
				
			case '?':
				prefix = PREFIX_NEUTRAL;
				p++;
				break;

			default:
				while (ispunct((unsigned char)(*p))) {
					SPF_response_add_error_ptr(spf_response,
									SPF_E_INVALID_PREFIX, NULL, p,
									"Invalid prefix '%c'", *p);
						p++;
				}
				break;
		}

		name_start = p;
		val_end = name_start + strcspn(p, " ");

		/* get the mechanism/modifier */
		if ( ! isalpha( (unsigned char)*p ) ) {
			/* We could just bail on this one. */
			SPF_response_add_error_ptr(spf_response,
							SPF_E_INVALID_CHAR, NULL, p,
							"Invalid character at start of mechanism");
			p += strcspn(p, " ");
			continue;
		}
		while ( isalnum( (unsigned char)*p ) || *p == '_' || *p == '-' )
			p++;

/* TODO: These or macros like them are used in several places. Merge. */
#define STREQ_SIZEOF(a, b) \
				(strncasecmp((a), (b), sizeof( (b) ) - 1) == 0)
#define STREQ_SIZEOF_N(a, b, n) \
				(((n) == sizeof(b) - 1) && (strncasecmp((a),(b),(n)) == 0))

		/* See if we have a modifier or a prefix */
		name_len = p - name_start;

		if (spf_server->debug)
			SPF_debugf("Name starts at  %s", name_start);

		switch ( *p ) 
		{
		case ':':
		case '/':
		case ' ':
		case '\0':
		compile_mech:		/* A bona fide label */
			
			/*
			 * parse the mechanism
			 */

			/* mechanisms default to PREFIX_PASS */
			if ( prefix == PREFIX_UNKNOWN )
				prefix = PREFIX_PASS;

			if ( STREQ_SIZEOF_N(name_start, "a", name_len) )
				mechtype = SPF_mechtype_find(MECH_A);
			else if ( STREQ_SIZEOF_N(name_start, "mx", name_len) )
				mechtype = SPF_mechtype_find(MECH_MX);
			else if ( STREQ_SIZEOF_N(name_start, "ptr", name_len) )
				mechtype = SPF_mechtype_find(MECH_PTR);
			else if ( STREQ_SIZEOF_N(name_start, "include", name_len) )
				mechtype = SPF_mechtype_find(MECH_INCLUDE);
			else if ( STREQ_SIZEOF_N(name_start, "ip4", name_len) )
				mechtype = SPF_mechtype_find(MECH_IP4);
			else if ( STREQ_SIZEOF_N(name_start, "ip6", name_len) )
				mechtype = SPF_mechtype_find(MECH_IP6);
			else if ( STREQ_SIZEOF_N(name_start, "exists", name_len) )
				mechtype = SPF_mechtype_find(MECH_EXISTS);
			else if ( STREQ_SIZEOF_N(name_start, "all", name_len) )
				mechtype = SPF_mechtype_find(MECH_ALL);
#ifdef SPF_ALLOW_DEPRECATED_DEFAULT
			else if ( STREQ_SIZEOF_N(name_start,
											"default=allow", name_len) )
			{
				SPF_response_add_warn_ptr(spf_response, SPF_E_INVALID_OPT,
								NULL, name_start,
								"Deprecated option 'default=allow'");
				mechtype = SPF_mechtype_find(MECH_ALL);
				prefix = PREFIX_PASS;
			}
			else if (STREQ_SIZEOF_N(name_start,
											"default=softfail",name_len))
			{
				SPF_response_add_warn_ptr(spf_response, SPF_E_INVALID_OPT,
								NULL, name_start,
								"Deprecated option 'default=softfail'");
				mechtype = SPF_mechtype_find(MECH_ALL);
				prefix = PREFIX_SOFTFAIL;
			}
			else if ( STREQ_SIZEOF_N(name_start,
											"default=deny", name_len) )
			{
				SPF_response_add_warn_ptr(spf_response, SPF_E_INVALID_OPT,
								NULL, name_start,
								"Deprecated option 'default=deny'");
				mechtype = SPF_mechtype_find(MECH_ALL);
				prefix = PREFIX_FAIL;
			}
			else if ( STREQ_SIZEOF(name_start, "default=") )
			{
				SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_OPT,
								NULL, name_start,
								"Invalid modifier 'default=...'");
				p = val_end;
				continue;
			}
#endif
			/* FIXME  the redirect mechanism needs to be moved to
			 * the very end */
			else if ( STREQ_SIZEOF_N(name_start, "redirect", name_len) )
				mechtype = SPF_mechtype_find(MECH_REDIRECT);
			else
			{
				SPF_response_add_error_ptr(spf_response, SPF_E_UNKNOWN_MECH,
								NULL, name_start,
								"Unknown mechanism found");
				p = val_end;
				continue;
			}

			if (mechtype == NULL) {
				return SPF_response_add_error_ptr(spf_response,
								SPF_E_INTERNAL_ERROR,
								NULL, name_start,
								"Failed to find specification for "
								"a recognised mechanism");
			}

			if (spf_server->debug)
				SPF_debugf("Adding mechanism type %d",
								(int)mechtype->mech_type);

			val_start = p;
			err = SPF_c_mech_add(spf_server,
							spf_record, spf_response,
							mechtype, prefix, &val_start);
			if (err == SPF_E_NO_MEMORY)
				return err;
			/* XXX Else do nothing. Continue for the next error. */
			/* We shouldn't have to worry about the child function
			 * updating the pointer. So we just use our 'well known'
			 * copy. */
			p = val_end;
			break;

		case '=':
			
			/*
			 * parse the modifier
			 */

			/* modifiers can't have prefixes */
			if (prefix != PREFIX_UNKNOWN)
				SPF_response_add_error_ptr(spf_response, SPF_E_MOD_W_PREF,
								NULL, name_start,
								"Modifiers may not have prefixes");
			prefix = PREFIX_UNKNOWN;	/* For redirect/include */

#ifdef SPF_ALLOW_DEPRECATED_DEFAULT
			/* Deal with legacy special case */
			if ( STREQ_SIZEOF(name_start, "default=") ) {
				/* Consider the whole 'default=foo' as a token. */
				p = val_end;
				name_len = p - name_start;
				goto compile_mech;
			}
#endif

			/* We treat 'redirect' as a mechanism. */
			if ( STREQ_SIZEOF(name_start, "redirect=") )
				goto compile_mech;

			p++;
			val_start = p;
			err = SPF_c_mod_add(spf_server,
							spf_record, spf_response,
							name_start, name_len, &val_start);
			if (err == SPF_E_NO_MEMORY)
				return err;
			/* XXX Else do nothing. Continue for the next error. */
			p = val_end;
			break;
			
			
		default:
			SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CHAR,
							NULL, p,
							"Invalid character in middle of mechanism");
			p = val_end;
			break;
		}
	}
	

	/*
	 * check for common mistakes
	 */
	SPF_record_lint(spf_server, spf_response, spf_record);


	/*
	 * do final cleanup on the record
	 */

	/* FIXME realloc (shrink) spfi buffers? */

	if (SPF_response_errors(spf_response) > 0) {
		for (i = 0; i < SPF_response_messages(spf_response); i++) {
			spf_error = SPF_response_message(spf_response, i);
			if (SPF_error_errorp(spf_error))
				return SPF_error_code(spf_error);
		}
		return SPF_response_add_error(spf_response,
						SPF_E_INTERNAL_ERROR,
						"Response has errors but can't find one!");
	}

	return SPF_E_SUCCESS;
}

SPF_errcode_t
SPF_record_compile_macro(SPF_server_t *spf_server,
								SPF_response_t *spf_response, 
								SPF_macro_t **spf_macrop,
								const char *record)
{
ALIGN_DECL(
	char			 buf[sizeof(SPF_macro_t) + SPF_MAX_MOD_LEN];
);
	SPF_macro_t		*spf_macro = (SPF_macro_t *)ALIGNED_DECL(buf);
	SPF_data_t		*data;
	SPF_errcode_t	 err;
	size_t			 size;
	
	data = SPF_macro_data(spf_macro);
	spf_macro->macro_len = 0;

	err = SPF_c_parse_macro(spf_server, spf_response,
					data, &spf_macro->macro_len, SPF_MAX_MOD_LEN,
					record, strlen(record),
					SPF_E_BIG_MOD, TRUE);
	if (err != SPF_E_SUCCESS)
		return err;

	/* XXX TODO: Tidy this up? */
	size = sizeof(SPF_macro_t) + spf_macro->macro_len;
	*spf_macrop = (SPF_macro_t *)malloc(size);
	if (!*spf_macrop)
		return SPF_E_NO_MEMORY;
	memcpy(*spf_macrop, ALIGNED_DECL(buf), size);

	return SPF_E_SUCCESS;
}
