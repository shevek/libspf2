#warning "Sorry, you will have to find a working realloc on your own"

#include "config.h"
#include <sys/types.h>

inline void *
rpl_realloc(ptr, size)
	void *ptr;
        size_t size;
{       
	return realloc(ptr, size);
}
