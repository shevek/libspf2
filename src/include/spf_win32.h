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

#ifndef INC_SPF_WIN32
#define INC_SPF_WIN32


#include <time.h>

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <ws2tcpip.h>
#include <windows.h>


/* ********************************************************************* */

/*
 * SPF startup and cleanup for Win32
 */

/*
 * These routines basically just startup and cleanup the Winsock layer
 * with a version is known to work with this library (version 2.2).
 * If Winsock startup and cleanup is already being performed by the
 * application, then these calls are not necessary.
 * 
 * Otherwise, startup must be done before any other calls, and cleanup
 * should be called when the application is done with the library.
 */
#ifdef _WIN32
int SPF_win32_startup();
int SPF_win32_cleanup();
#endif



#define __attribute__(n)



#endif

#endif
