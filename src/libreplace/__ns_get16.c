/* #include "port_before.h" */
#include "config.h"

#ifdef STDC_HEADERS
# include <stdio.h>
#endif

#include <sys/types.h>

#include <netinet/in.h>
#include "arpa_nameser.h"


u_int
__ns_get16(src)
	const u_char *src;
{
        u_int dst;

	NS_GET16(dst, src);
	return (dst);
}
