#include "test.h"
#include <sodium.h>


unsigned char test_random_counter;


int main(void) {
	suite_key_storage_generate();
	suite_key_storage_encode();
	return 0;
}


void test_random(void * const buf, const size_t size) {
	unsigned char *uchar_buf = buf;

	for(size_t i = 0; i < size; i++)
		uchar_buf[i] = test_random_counter++;
}


int test_sign_keypair(unsigned char *public_key, unsigned char *secret_key) {
	unsigned char seed[32];
	test_random(seed, sizeof seed);

	return crypto_sign_ed25519_seed_keypair(public_key, secret_key, seed);
}
