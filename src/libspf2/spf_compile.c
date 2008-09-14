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

/* This is greater than any possible total mechanism or modifier.
 *	 SPF_MAX_MOD_LEN  + SPF_MAX_STR_LEN
 *	 SPF_MAX_MECH_LEN + SPF_MAX_STR_LEN
 */
#define SPF_RECORD_BUFSIZ	  4096



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
	int		 i;
	for (i = 0; i < spf_num_mechanisms; i++) {
			if (spf_mechtypes[i].mech_type == mech_type)
			return &spf_mechtypes[i];
	}
	return NULL;
}

static void
SPF_c_ensure_capacity(void **datap, size_t *sizep, size_t length)
{
	size_t		 size = *sizep;
	if (length > size)
		size = length + (length / 4);
	if (size > *sizep) {
		*datap = realloc(*datap, size);
		*sizep = size;
	}
}

/* If a struct for IP addresses is added which itself contains a
 * CIDR field, then this must be modified to take a (cidr *) rather
 * than a (SPF_data_cidr_t *) */
static SPF_errcode_t
SPF_c_parse_cidr_ip6(SPF_response_t *spf_response,
				unsigned char *maskp,
				const char **startp, const char **endp)
{
	int		 mask;

	mask = strtoul(*startp + 1, NULL, 10);

	if (mask > 128) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, *startp,
						"Invalid IPv6 CIDR netmask (>128)");
	}
	else if (mask == 0) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, *startp,
						"Invalid IPv6 CIDR netmask (=0)");
	}
	else if (mask == 128) {
		mask = 0;
	}

	*maskp = mask;

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_c_parse_cidr_ip4(SPF_response_t *spf_response,
				unsigned char *maskp,
				const char **startp, const char **endp)
{
	int		 mask;

	mask = strtoul(*startp + 1, NULL, 10);

	if ( mask > 32 ) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, *startp,
						"Invalid IPv4 CIDR netmask (>32)");
	}
	else if ( mask == 0 ) {
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, *startp,
						"Invalid IPv4 CIDR netmask (=0)");
	}
	else if ( mask == 32 ) {
		mask = 0;
	}

	*maskp = mask;

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_c_parse_cidr(SPF_response_t *spf_response,
				SPF_data_cidr_t *data,
				const char **startp, const char **endp)
{
	SPF_errcode_t		 err;
	const char				*start;
	const char				*end;

	end = *endp;
	start = end - 1;

	memset(data, 0, sizeof(SPF_data_cidr_t));
	data->parm_type = PARM_CIDR;

	/* find the beginning of the CIDR length notation */
	while( isdigit( (unsigned char)( *start ) ) )
		start--;

	/* Something is frying my brain and I can't pull an invariant
	 * out of this suitable for resetting *endp. So I nested the
	 * 'if's instead. Perhaps I'll manage to refactor later. */

	if ( start != (end - 1)  &&  *start == '/' ) {
		if ( start[-1] == '/' ) {
			/* get IPv6 CIDR length */
			err = SPF_c_parse_cidr_ip6(spf_response, &data->ipv6, &start, &end);
			if (err)
					return err;
			/* now back up and see if there is a ipv4 cidr length */
			end = start - 1;		/* The first '/' */
			start = end - 1;
			while( isdigit( (unsigned char)( *start ) ) )
				start--;

			/* get IPv4 CIDR length */
			if ( start != (end - 1)  &&  *start == '/' ) {
				err = SPF_c_parse_cidr_ip4(spf_response, &data->ipv4, &start, &end);
				if (err)
					return err;
				*endp = start;
			}
			else {
				*endp = end;
			}
		}
		else {
			/* get IPv4 CIDR length */
			err = SPF_c_parse_cidr_ip4(spf_response, &data->ipv4, &start, &end);
			if (err)
				return err;
			*endp = start;
		}
	}

	return SPF_E_SUCCESS;
}

static SPF_errcode_t
SPF_c_parse_var(SPF_response_t *spf_response, SPF_data_var_t *data,
				const char **startp, const char **endp,
				int is_mod)
{
	const char		*token;
	const char		*p;
	char		 c;
	int				 val;

	memset(data, 0, sizeof(SPF_data_var_t));

	p = *startp;

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
	if ( val > 128  ||  (val == 0 && p != token) )
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
					big_err, NULL, start,							\
					"SPF domainspec too long "						\
					"(%d chars, %d max)",							\
					(_val) + (_len), _max);							\
			}														\
			(_val) += _align_sz(_len);								\
		} while(0)

#define SPF_INIT_STRING_LITERAL()		do { \
			data->ds.parm_type = PARM_STRING;						\
			data->ds.len = 0;										\
			dst = SPF_data_str( data );								\
			ds_len = 0;												\
		} while(0)

#define SPF_FINI_STRING_LITERAL()		do { \
			if ( ds_len > 0 ) {										\
				if ( ds_len > SPF_MAX_STR_LEN ) {					\
					return SPF_response_add_error_ptr(spf_response,		\
									SPF_E_BIG_STRING, NULL, start,	\
								"String literal too long "			\
								"(%d chars, %d max)",				\
								ds_len, SPF_MAX_STR_LEN);			\
				}													\
				data->ds.len = ds_len;								\
				len = sizeof( *data ) + ds_len;						\
				SPF_ADD_LEN_TO(*data_len, len, max_len);			\
				data = SPF_data_next( data );						\
				ds_len = 0;											\
			}														\
		} while(0)

static SPF_errcode_t
SPF_c_parse_macro(SPF_server_t *spf_server,
				SPF_response_t *spf_response,
				SPF_data_t *data, size_t *data_len,
				const char **startp, const char **endp,
				size_t max_len, SPF_errcode_t big_err,
				int is_mod)
{
	SPF_errcode_t		 err;
			/* Generic parsing iterators and boundaries */
	const char			*start;
	const char			*end;
	const char			*p;
	size_t				len;
			/* For parsing strings. */
	char				*dst;
	size_t				 ds_len;

	start = *startp;
	end = *endp;

	/*
	 * Create the data blocks
	 */

	p = start;

	/* Initialise the block as a string. If ds_len == 0 later, we
	 * will just clobber it. */
	SPF_INIT_STRING_LITERAL();

	while ( p != end ) {
		len = strcspn( p, " %" );
		if (len > 0) {				/* An optimisation */
			if ( p + len > end )	/* Don't re-parse the CIDR mask */
				len = end - p;
			if (spf_server->debug)
				SPF_debugf("Adding string literal (%d): '%*.*s'",
								(int)len, (int)len, (int)len, p);
			memcpy( dst, p, len );
			ds_len += len;
			dst += len;
			p += len;

			/* If len == 0 then we never entered the while(). Thus
			 * if p == end, then len != 0 and we reach this test. */
			if ( p == end )
				break;
		}

		/* Now, we must have a %-escape code, since if we hit a
		 * space, then we are at the end. */
		p++;
		switch ( *p )
		{
		case '%':
			*dst++ = '%';
			ds_len++;
			p++;
			break;
			
		case '_':
			*dst++ = ' ';
			ds_len++;
			p++;
			break;

		case '-':
			*dst++ = '%'; *dst++ = '2'; *dst++ = '0';
			ds_len += 3;
			p++;
			break;

		default:
			/* SPF spec says to treat it as a literal, not
			 * SPF_E_INVALID_ESC */
			/* FIXME   issue a warning? */
			*dst++ = '%';
			ds_len++;
			break;

		case '{':  /*vi:}*/
			SPF_FINI_STRING_LITERAL();

			/* this must be a variable */
			p++;
			err = SPF_c_parse_var(spf_response, &data->dv, &p, &end, is_mod);
			if (err != SPF_E_SUCCESS)
				return err;
			p += strcspn(p, "} ");
			if (*p == '}')
				p++;
			else if (*p == ' ')
				return SPF_response_add_error_ptr(spf_response,
						SPF_E_INVALID_VAR,
						*startp, p,
						"Unterminated variable?");


			len = SPF_data_len(data);
			SPF_ADD_LEN_TO(*data_len, len, max_len);
			data = SPF_data_next( data );

			SPF_INIT_STRING_LITERAL();

			break;
		}
	}

	SPF_FINI_STRING_LITERAL();

	return SPF_E_SUCCESS;

}

/* What a fuck-ugly prototype. */
static SPF_errcode_t
SPF_c_parse_domainspec(SPF_server_t *spf_server,
				SPF_response_t *spf_response,
				SPF_data_t *data, size_t *data_len,
				const char **startp, const char **endp,
				size_t max_len, SPF_errcode_t big_err,
				SPF_cidr_t cidr_ok, int is_mod)
{
	SPF_errcode_t		 err;
			/* Generic parsing iterators and boundaries */
	const char			*start;
	const char			*end;
	const char			*p;
	size_t				len;

	p = *startp;
	start = *startp;
	end = *endp;

	if (spf_server->debug)
		SPF_debugf("Parsing domainspec starting at %s, cidr is %s",
						p,
						cidr_ok == CIDR_OPTIONAL ? "optional" :
						cidr_ok == CIDR_ONLY ? "only" :
						cidr_ok == CIDR_NONE ? "forbidden" :
						"ERROR!"
						);

	/*
	 * create the CIDR length info
	 */
	if ( cidr_ok == CIDR_OPTIONAL  ||  cidr_ok == CIDR_ONLY ) 
	{
		err = SPF_c_parse_cidr(spf_response, &data->dc, &start, &end);
		if (err != SPF_E_SUCCESS)
			return err;
		if (data->dc.ipv4 != 0  ||  data->dc.ipv6 != 0) {
			len = SPF_data_len(data);
			SPF_ADD_LEN_TO(*data_len, len, max_len);
			data = SPF_data_next(data);
		}
	}

	if ( cidr_ok == CIDR_ONLY  &&  start != end ) {
		/* We had a mechanism followed by a '/', thus it HAS to be
		 * a CIDR, and the peculiar-looking error message is
		 * justified. However, we don't know _which_ CIDR. */
		return SPF_response_add_error_ptr(spf_response, SPF_E_INVALID_CIDR,
						NULL, start,
						"Invalid CIDR after mechanism");
	}

	return SPF_c_parse_macro(spf_server, spf_response, data, data_len,
				&start, &end, max_len, big_err, is_mod);
}


static SPF_errcode_t
SPF_c_parse_ip4(SPF_response_t *spf_response, SPF_mech_t *mech, char const **startp)
{
	const char				*start;
	const char				*end;
	const char				*p;

	char				 buf[ INET_ADDRSTRLEN ];
	size_t				 len;
	int						 err;

	unsigned char		 mask;
	struct in_addr		*addr;

	start = *startp + 1;
	len = strcspn(start, " ");
	end = start + len;
	p = end - 1;

	mask = 0;
	while (isdigit( (unsigned char)(*p) ))
		p--;
	if (p != (end - 1) && *p == '/') {
		err = SPF_c_parse_cidr_ip4(spf_response, &mask, &p, &end);
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

static SPF_errcode_t
SPF_c_parse_ip6(SPF_response_t *spf_response, SPF_mech_t *mech, char const **startp)
{
	const char				*start;
	const char				*end;
	const char				*p;

	char				 buf[ INET_ADDRSTRLEN ];
	size_t				 len;
	int						 err;

	unsigned char		 mask;
	struct in6_addr		*addr;

	start = *startp + 1;
	len = strcspn(start, " ");
	end = start + len;
	p = end - 1;

	mask = 0;
	while (isdigit( (unsigned char)(*p) ))
		p--;
	if (p != (end - 1) && *p == '/') {
		err = SPF_c_parse_cidr_ip6(spf_response, &mask, &p, &end);
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


static SPF_errcode_t
SPF_c_mech_add(SPF_server_t *spf_server,
				SPF_record_t *spf_record, SPF_response_t *spf_response,
				const SPF_mechtype_t *mechtype, int prefix,
				const char **mech_value)
{
	char				 buf[SPF_RECORD_BUFSIZ];
	SPF_mech_t				*spf_mechanism = (SPF_mech_t *)buf;
	SPF_data_t				*data;
	size_t						 data_len;
	const char				*end;
	size_t						 len;

	SPF_errcode_t		 err;

	memset(buf, 'B', sizeof(buf));	/* Poison the buffer. */
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

	end = *mech_value + strcspn(*mech_value, " ");

	switch (mechtype->mech_type) {
		/* We know the properties of IP4 and IP6. */
			case MECH_IP4:
			if (**mech_value == ':') {
				err = SPF_c_parse_ip4(spf_response, spf_mechanism, mech_value);
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
				err = SPF_c_parse_ip6(spf_response, spf_mechanism, mech_value);
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
					(*mech_value)++;
					err = SPF_c_parse_domainspec(spf_server,
									spf_response, data, &data_len,
									mech_value, &end,
									SPF_MAX_MECH_LEN, SPF_E_BIG_MECH,
									mechtype->has_cidr, FALSE );
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
									spf_response, data, &data_len,
									mech_value, &end,
									SPF_MAX_MECH_LEN, SPF_E_BIG_MECH,
									CIDR_ONLY, FALSE );
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
		SPF_c_ensure_capacity((void **)&spf_record->mech_first,
							&spf_record->mech_size,
							spf_record->mech_len + len);
		memcpy( (char *)spf_record->mech_first + spf_record->mech_len,
			spf_mechanism,
			len);
		spf_record->mech_len += len;
		spf_record->num_mech++;
	}

	*mech_value = end;

	return err;
}

static SPF_errcode_t
SPF_c_mod_add(SPF_server_t *spf_server,
				SPF_record_t *spf_record, SPF_response_t *spf_response,
				const char *mod_name, size_t name_len,
				const char **mod_value)
{
	char				 buf[SPF_RECORD_BUFSIZ];
	SPF_mod_t			*spf_modifier = (SPF_mod_t *)buf;
	SPF_data_t			*data;
	size_t				 data_len;
	const char			*end;
	size_t				 len;

	SPF_errcode_t		 err;

	memset(buf, 'A', sizeof(buf));
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

	end = *mod_value + strcspn(*mod_value, " ");

	err = SPF_c_parse_domainspec(spf_server,
					spf_response, data, &data_len,
					mod_value, &end,
					SPF_MAX_MOD_LEN, SPF_E_BIG_MOD,
					CIDR_NONE, TRUE );
	spf_modifier->data_len = data_len;
	len += data_len;

	/* Copy the thing in. */
	if (err == SPF_E_SUCCESS) {
		SPF_c_ensure_capacity((void **)&spf_record->mod_first,
							&spf_record->mod_size,
							spf_record->mod_len + len);
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



/*
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
	int					 name_len;

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

	if ( strncmp( p, SPF_VER_STR, sizeof( SPF_VER_STR )-1 ) != 0 )
		return SPF_response_add_error_ptr(spf_response, SPF_E_NOT_SPF,
						NULL, p,
						"Could not find a valid SPF record");
	p += sizeof( SPF_VER_STR ) - 1;

	if ( *p != '\0' && *p != ' ' )
		return SPF_response_add_error_ptr(spf_response, SPF_E_NOT_SPF,
						NULL, p,
						"Could not find a valid SPF record");

	spf_record = SPF_record_new(spf_server, record);
	spf_record->version = 1;
	*spf_recordp = spf_record;

	/*
	 * parse the SPF record
	 */
	while( *p != '\0' )
	{
		/* TODO WARN: If it's a \n or a \t */
		/* skip to the next token */
		while( *p == ' ' )
			p++;

		if (*p == '\0' )
			break;

		/* see if we have a valid prefix */
		prefix = PREFIX_UNKNOWN;
		switch( *p )
		{
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
			while ( ispunct( (unsigned char)( *p ) ) ) {
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
			if ( err )
				/* Do nothing. Continue for the next error. */ ;
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
			if ( err )
				/* Do nothing. Continue for the next error. */ ;
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
	char			 buf[SPF_RECORD_BUFSIZ];
	SPF_macro_t		*spf_macro = (SPF_macro_t *)buf;
	SPF_data_t		*data;
	SPF_errcode_t	 err;
	const char		*end;
	size_t			 size;
	
	data = SPF_macro_data(spf_macro);
	spf_macro->macro_len = 0;

	end = record + strlen(record);

	err = SPF_c_parse_macro(spf_server, spf_response,
					data, &spf_macro->macro_len,
					&record, &end,
					SPF_MAX_MOD_LEN, SPF_E_BIG_MOD, TRUE);
	if (err != SPF_E_SUCCESS)
		return err;

	/* XXX TODO: Tidy this up? */
	size = sizeof(SPF_macro_t) + spf_macro->macro_len;
	*spf_macrop = (SPF_macro_t *)malloc(size);
	memcpy(*spf_macrop, buf, size);

	return SPF_E_SUCCESS;
}
