#include "impl.h"
#include <sodium.h>


void (*internal_random)(void * const buf, const size_t size) = randombytes_buf;

