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


#include "spf.h"
#include "spf_dns.h"
#include "spf_response.h"

SPF_response_t *
SPF_response_new(SPF_request_t *spf_request)
{
	SPF_response_t	*rp;

	rp = (SPF_response_t *)malloc(sizeof(SPF_response_t));
	if (! rp)
		return rp;
	memset(rp, 0, sizeof(SPF_response_t));

	rp->spf_request = spf_request;
	rp->result = SPF_RESULT_INVALID;

	return rp;
}

void
SPF_response_free(SPF_response_t *rp)
{
	int	 i;

	if (rp->received_spf)
		free(rp->received_spf);
	/* Don't free received_spf_value - it points into received_spf */
	if (rp->header_comment)
		free(rp->header_comment);
	if (rp->smtp_comment)
		free(rp->smtp_comment);
	if (rp->explanation)
		free(rp->explanation);

	if (rp->errors) {
		for (i = 0; i < rp->errors_length; i++) {
			free(rp->errors[i].message);
		}
		free(rp->errors);
	}

	free(rp);
}

static SPF_response_t *
SPF_response_choose(SPF_response_t *yes, SPF_response_t *no)
{
	SPF_response_free(no);
	return yes;
}

/*
 * This is rather a guess-and-fiddle routine which tries to pick
 * the best of both worlds. It doesn't currently deal with error
 * messages at all.
 */
SPF_response_t *
SPF_response_combine(SPF_response_t *main, SPF_response_t *r2mx)
{
	switch (SPF_response_result(main)) {
		case SPF_RESULT_INVALID:
			/* If the main failed entirely, use the secondary */
			return SPF_response_choose(r2mx, main);

		case SPF_RESULT_PASS:
			/* If the main passed, use main */
			return SPF_response_choose(main, r2mx);

		case SPF_RESULT_NEUTRAL:
			/* If the main is neutral: */
			switch (SPF_response_result(r2mx)) {
				case SPF_RESULT_PASS:
					/* Use the secondary if it passed */
					return SPF_response_choose(r2mx, main);
				default:
					/* Otherwise just use the main */
					return SPF_response_choose(main, r2mx);
			}

		case SPF_RESULT_FAIL:
			/* If the main failed, use the secondary */
			return SPF_response_choose(r2mx, main);

		case SPF_RESULT_TEMPERROR:
		case SPF_RESULT_PERMERROR:
		case SPF_RESULT_SOFTFAIL:
		default:
			/* If the main is peculiar, including softfail: */
			switch (SPF_response_result(r2mx)) {
				case SPF_RESULT_PASS:
				case SPF_RESULT_NEUTRAL:
				case SPF_RESULT_SOFTFAIL:
					/* Use the secondary if it didn't fail */
					return SPF_response_choose(r2mx, main);
				default:
					/* Otherwise just use the main */
					return SPF_response_choose(main, r2mx);
			}
	}
}

SPF_result_t
SPF_response_result(SPF_response_t *rp)
{
	return rp->result;
}

SPF_reason_t
SPF_response_reason(SPF_response_t *rp)
{
	return rp->reason;
}

SPF_errcode_t
SPF_response_errcode(SPF_response_t *rp)
{
	return rp->err;
}

const char *
SPF_response_get_received_spf(SPF_response_t *rp)
{
	return rp->received_spf;
}

const char *
SPF_response_get_received_spf_value(SPF_response_t *rp)
{
	return rp->received_spf_value;
}

const char *
SPF_response_get_header_comment(SPF_response_t *rp)
{
	return rp->header_comment;
}

const char *
SPF_response_get_smtp_comment(SPF_response_t *rp)
{
	return rp->smtp_comment;
}

const char *
SPF_response_get_explanation(SPF_response_t *rp)
{
	return rp->explanation;
}

/* Error manipulation functions */

#define SPF_ERRMSGSIZE		4096

static SPF_errcode_t
SPF_response_add_error_v(SPF_response_t *rp,
				SPF_errcode_t code, int is_error,
				const char *text, int idx,
				const char *format, va_list ap)
{
	SPF_error_t	*tmp;
	char		 buf[SPF_ERRMSGSIZE];
	int			 size;

	/* TODO: Use text and idx */

	if (!format)
		format = SPF_strerror(code);
    size = vsnprintf(buf, sizeof(buf), format, ap);
	if (text != NULL) {
		snprintf(&buf[size], sizeof(buf) - size,
				" near '%.12s'", &text[idx]);
	}
	buf[SPF_ERRMSGSIZE - 1] = '\0';

	if (rp->errors_length == rp->errors_size) {
		size = rp->errors_size + (rp->errors_size / 4) + 4;
		tmp = (SPF_error_t *)realloc(rp->errors, size * sizeof(SPF_error_t));
		if (! tmp) {
			SPF_error("Failed to allocate memory for extra response error");
			return code;
		}
		rp->errors = tmp;
		rp->errors_size = size;
	}

	rp->errors[rp->errors_length].code = code;
	rp->errors[rp->errors_length].is_error = is_error;
	/* If we are a memory error, this might fail. */
	rp->errors[rp->errors_length].message = strdup(buf);
	rp->errors_length++;

	return code;
}

#define SPF_ADD_ERROR(_ise, _txt, _ix) \
    va_list	 ap; va_start(ap, format); \
	SPF_response_add_error_v(rp, code, _ise, _txt, _ix, format, ap); \
	rp->num_errors++; \
    va_end(ap); return code;
#define SPF_ADD_WARN(_ise, _txt, _ix) \
    va_list	 ap; va_start(ap, format); \
	SPF_response_add_error_v(rp, code, _ise, _txt, _ix, format, ap); \
    va_end(ap); return code;

SPF_errcode_t
SPF_response_add_error_ptr(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *text, const char *tptr,
				const char *format, ...)
{
	SPF_ADD_ERROR(1, text ? text : tptr, text ? (tptr - text) : 0);
}

SPF_errcode_t
SPF_response_add_error_idx(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *text, int idx,
				const char *format, ...)
{
	SPF_ADD_ERROR(1, text, idx);
}

SPF_errcode_t
SPF_response_add_error(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *format, ...)
{
	SPF_ADD_ERROR(1, NULL, 0);
}

SPF_errcode_t
SPF_response_add_warn_ptr(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *text, const char *tptr,
				const char *format, ...)
{
	SPF_ADD_WARN(0, text ? text : tptr, text ? (tptr - text) : 0);
}

SPF_errcode_t
SPF_response_add_warn_idx(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *text, int idx,
				const char *format, ...)
{
	SPF_ADD_WARN(0, text, idx);
}

SPF_errcode_t
SPF_response_add_warn(SPF_response_t *rp,
				SPF_errcode_t code,
				const char *format, ...)
{
	SPF_ADD_WARN(0, NULL, 0);
}

int
SPF_response_messages(SPF_response_t *rp)
{
	return rp->errors_length;
}

int
SPF_response_errors(SPF_response_t *rp)
{
	return rp->num_errors;
}

int
SPF_response_warnings(SPF_response_t *rp)
{
	return rp->errors_length - rp->num_errors;
}

SPF_error_t *
SPF_response_message(SPF_response_t *rp, int idx)
{
	return &rp->errors[idx];
}

SPF_errcode_t   
SPF_error_code(SPF_error_t *err)
{
	return err->code;
}

const char *
SPF_error_message(SPF_error_t *err)
{
	return err->message;
}

char
SPF_error_errorp(SPF_error_t *err)
{
	return err->is_error;
}
