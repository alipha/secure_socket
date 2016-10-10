#ifndef SS_COMMON_H
#define SS_COMMON_H

#include <stdint.h>
#include <stddef.h>


#ifndef TRUE
	#define TRUE 1
#endif

#ifndef FALSE
	#define FALSE 0
#endif

#ifndef BOOL
	#define BOOL int
#endif


#define SS_SUCCESS                   0
#define SS_ERROR_NULL_ARGUMENT       1
#define SS_ERROR_OUT_OF_MEMORY       2
#define SS_ERROR_BUFFER_TOO_SMALL    3
#define SS_ERROR_INVALID_PASSWORD    4
#define SS_ERROR_BAD_ENCODED_FORMAT  5
#define SS_ERROR_BAD_ENCODED_LENGTH	 6
#define SS_ERROR_INVALID_PORT        7


typedef uint32_t ss_error;


void xor_bytes(unsigned char *dest, unsigned char *src, size_t len);


#endif
