#warning "Sorry, you will have to find a working memcmp on your own"

#include "config.h"
#include <sys/types.h>

inline int
rpl_memcmp(b1, b2, len)
	void *b1;
	void *b2;
	size_t len;
{
	return memcmp(b1, b2, len);
}
