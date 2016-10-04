#include "common.h"


void xor_bytes(unsigned char *dest, unsigned char *src, size_t len) {
	for(size_t i = 0; i < len; i++)
		dest[i] ^= src[i];
}

