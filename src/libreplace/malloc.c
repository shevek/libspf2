#warning "Sorry, you will have to find a working malloc on your own"

#include "config.h"
#include <sys/types.h>

inline void *
rpl_malloc(size)
	size_t size;
{
	return malloc(size);
}
