#include "test.h"


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


