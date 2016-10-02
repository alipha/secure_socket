#ifndef SS_BASE64_H
#define SS_BASE64_H

#include <stdint.h>

size_t ss_to_base64(char *dst, size_t dst_len, const void *src, size_t src_len);

const char *ss_from_base64(void *dst, size_t *dst_len, const char *src);

#endif
