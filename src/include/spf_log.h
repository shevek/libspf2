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



#ifndef INC_SPF_LOG
#define INC_SPF_LOG

/**
 * @file
 * Error messages and warnings generated internally by the library call
 * these routines.  By default, the messages go to stderr, but you can
 * define your own routines to deal with the messages instead.
 *
 * To use the syslog routines, add code such as:
 *
 *  openlog(logPrefix,LOG_PID|LOG_CONS|LOG_NDELAY|LOG_NOWAIT,LOG_MAIL);
 *
 *  SPF_error_handler = SPF_error_syslog;
 *  SPF_warning_handler = SPF_warning_syslog;
 *  SPF_info_handler = SPF_info_syslog;
 *  SPF_debug_handler = SPF_debug_syslog;
 */

#include <stdarg.h>


#define SPF_error(errmsg) SPF_errorx( __FILE__, __LINE__, "%s", errmsg )
void SPF_errorx( const char *file, int line, const char *format, ... ) __attribute__ ((noreturn)) __attribute__ ((format (printf, 3, 4)));
void SPF_errorx2( const char *format, ... );
void SPF_errorv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((noreturn)) __attribute__ ((format (printf, 3, 0)));

#define SPF_warning(errmsg) SPF_warningx( __FILE__, __LINE__, "%s", errmsg )
void SPF_warningx( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_warningx2( const char *format, ... );
void SPF_warningv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));

#define SPF_info(errmsg) SPF_infox( __FILE__, __LINE__, "%s", errmsg )
void SPF_infox( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_infox2( const char *format, ... );
void SPF_infov( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));

#define SPF_debug(errmsg) SPF_debugx( __FILE__, __LINE__, "%s", errmsg )
void SPF_debugx( const char *file, int line, const char *format, ... ) __attribute__ ((format (printf, 3, 4)));
void SPF_debugx2( const char *format, ... );
void SPF_debugv( const char *file, int line, const char *format, va_list ap ) __attribute__ ((format (printf, 3, 0)));


#if defined( __STDC_VERSION__ ) && __STDC_VERSION__ >= 199901L

#define SPF_errorf(format, ... ) SPF_errorx( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_warningf(format, ... ) SPF_warningx( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_infof(format, ... ) SPF_infox( __FILE__, __LINE__, format, __VA_ARGS__ )
#define SPF_debugf(format, ... ) SPF_debugx( __FILE__, __LINE__, format, ##__VA_ARGS__ )

#elif defined( __GNUC__ )

#define SPF_errorf(format... ) SPF_errorx( __FILE__, __LINE__, format )
#define SPF_warningf(format... ) SPF_warningx( __FILE__, __LINE__, format )
#define SPF_infof(format... ) SPF_infox( __FILE__, __LINE__, format )
#define SPF_debugf(format... ) SPF_debugx( __FILE__, __LINE__, format )

#else

#define SPF_errorf	SPF_errorx2
#define SPF_warningf	SPF_warningx2
#define SPF_infof	SPF_infox2
#define SPF_debugf	SPF_debugx2

#endif


/* These message handler routines print to stderr or stdout, as appropriate. */

void SPF_error_stdio( const char *file, int line, const char *errmsg ) __attribute__ ((noreturn));
void SPF_warning_stdio( const char *file, int line, const char *errmsg );
void SPF_info_stdio( const char *file __attribute__ ((unused)), int line __attribute__ ((unused)), const char *errmsg );
void SPF_debug_stdio( const char *file, int line, const char *errmsg );


/* These message handler routines send messages to syslog */

void SPF_error_syslog( const char *file, int line, const char *errmsg ) __attribute__ ((noreturn));
void SPF_warning_syslog( const char *file, int line, const char *errmsg );
void SPF_info_syslog( const char *file __attribute__ ((unused)), int line __attribute__ ((unused)), const char *errmsg );
void SPF_debug_syslog( const char *file, int line, const char *errmsg );

/* FYI only -- can't be changed without recompiling the library */
#define SPF_DEFAULT_ERROR_HANDLER	SPF_error_stdio
#define SPF_DEFAULT_WARNING_HANDLER	SPF_warning_stdio
#define SPF_DEFAULT_INFO_HANDLER	SPF_info_stdio
#define SPF_DEFAULT_DEBUG_HANDLER	SPF_debug_stdio


/*
 * You can assign these global function pointers to whatever routines
 * you want to handle the various types of messages.  Setting them to NULL
 * will cause the messages to be ignored.
 */
 
extern void (*SPF_error_handler)( const char *, int, const char * ) __attribute__ ((noreturn));
extern void (*SPF_warning_handler)( const char *, int, const char * );
extern void (*SPF_info_handler)( const char *, int, const char * );
extern void (*SPF_debug_handler)( const char *, int, const char * );

#define SPF_ASSERT_NOTNULL(x) \
	do { if ((x) == NULL) SPF_error(#x " is NULL"); } while(0)




#endif
