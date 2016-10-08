#ifndef SS_TEST_H
#define SS_TEST_H

#include <stddef.h>


void test_random(void * const buf, const size_t size);
int test_sign_keypair(unsigned char *public_key, unsigned char *secret_key);


void suite_key_storage_generate(void);
void suite_key_storage_encode(void);


extern unsigned char test_random_counter;


#endif
