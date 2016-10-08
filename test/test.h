#ifndef SS_TEST_H
#define SS_TEST_H

#include <stddef.h>


void test_random(void * const buf, const size_t size);

void suite_key_storage_generate(void);
void suite_key_storage_encode(void);


extern unsigned char test_random_counter;


#endif
