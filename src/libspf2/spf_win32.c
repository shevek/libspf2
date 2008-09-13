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

#ifdef _WIN32

#include "spf_win32_internal.h"

int SPF_win32_startup()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) 
		return 0;
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
        HIBYTE( wsaData.wVersion ) != 2 )
	{
	    WSACleanup();
        return 0;
    }

	return 1;
}

int SPF_win32_cleanup()
{
	return WSACleanup();
}

char *inet_ntop( int af, const void *src, char *dst, size_t size )
{
	void	*pSrc_sockaddr;
	struct	sockaddr_in		src_sockaddr;
	struct	sockaddr_in6	src6_sockaddr;
	DWORD	src_size;
	DWORD	temp;
	int		result;
	DWORD	error;

	switch( af )
	{
	case AF_INET:
		src_sockaddr.sin_family = AF_INET;
		src_sockaddr.sin_port = 0;
		memcpy( &src_sockaddr.sin_addr, src, sizeof( struct in_addr ) );
		pSrc_sockaddr = &src_sockaddr;
		src_size = sizeof( struct sockaddr_in );
		break;
	case AF_INET6:
		src6_sockaddr.sin6_family = AF_INET6;
		src6_sockaddr.sin6_port = 0;
		src6_sockaddr.sin6_flowinfo = 0;
		src6_sockaddr.sin6_scope_id = 0;
		memcpy( &src6_sockaddr.sin6_addr, src, sizeof( struct in6_addr ) );
		pSrc_sockaddr = &src6_sockaddr;
		src_size = sizeof( struct sockaddr_in6 );
		break;
	default:
		return NULL;
	}

	temp = size;
	result = WSAAddressToStringA( (LPSOCKADDR)pSrc_sockaddr, src_size, 
		NULL, dst, &temp );
	
	error = GetLastError();

	if (result == 0)
		// Success
		return dst;
	else
		// Failure
		return NULL;
}

int inet_pton( int af, const char *src, void *dst )
{
	/* IPv6 is largest buffer, so use it for both */
	struct	sockaddr_in6	dst_sockaddr;
	struct	sockaddr_in6	*pDst_sockaddr;
	int		dst_size;
	int		result;
	DWORD	error;

	pDst_sockaddr = &dst_sockaddr;

	switch( af )
	{
	case AF_INET:
		dst_size = sizeof( struct sockaddr_in );
		break;
	case AF_INET6:
		dst_size = sizeof( struct sockaddr_in6 );
		break;
	default:
		return 0;
	}

	result = WSAStringToAddressA( src, af, NULL, 
		(LPSOCKADDR)pDst_sockaddr, &dst_size );

	if ( result != 0 )
	{
		error = GetLastError();
		return error;
		return 0;
	}

	switch( af )
	{
	case AF_INET:
		memcpy( dst, &((struct sockaddr_in*)pDst_sockaddr)->sin_addr, 
			sizeof( struct in_addr ) );
		break;
	case AF_INET6:
		memcpy( dst, &pDst_sockaddr->sin6_addr, 
			sizeof( struct in6_addr ) );
		break;
	}

	return 1;
}

int gethostnameFQDN( char *name, int namelen )
{
    int result;
    int fullnamelen;
    struct hostent *he;

    result = gethostname( name, namelen );

    if ( result == 0 )
    {
        he = gethostbyname( name );

        if (he != NULL)
        {
            fullnamelen = strlen( he->h_name );

            if (fullnamelen < namelen)
                strcpy( name, he->h_name );
        }
    }

    return result;
}

#endif
