/* #include "port_before.h" */
#include "config.h"

#ifdef STDC_HEADERS
# include <stdio.h>
#endif

#include <sys/types.h>

#include <netinet/in.h>
#include "arpa_nameser.h"



int __ns_msg_getflag(ns_msg handle, int flag) {
	return(((handle)._flags & _ns_flagdata[flag].mask) >> _ns_flagdata[flag].shift);
}

