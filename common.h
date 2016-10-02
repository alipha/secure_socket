#ifndef SS_COMMON_H
#define SS_COMMON_H

#include <stdint.h>


#ifndef TRUE
	#define TRUE 1
#endif

#ifndef FALSE
	#define FALSE 0
#endif

#ifndef BOOL
	#define BOOL int
#endif


#define SS_SUCCESS				0x00000000U
#define SS_ERROR_OUT_OF_MEMORY	0x00000001U



typedef uint32_t ss_error;


#endif
