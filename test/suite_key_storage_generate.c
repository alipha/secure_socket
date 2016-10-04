#include "test.h"
#include "../key_storage.h"
#include "../secure_socket.h"
#include "../impl.h"
#include <assert.h>
#include <string.h>
#include <sodium.h>


void test_generate_key_pair_no_password(void);
void test_generate_key_pair_with_password(void);
void test_generate_shared_key_no_password(void);
void test_generate_shared_key_with_password(void);


void suite_key_storage_generate() {
	puts("Start:   suite_key_storage_generate");
	test_generate_key_pair_no_password();
	test_generate_key_pair_with_password();
	test_generate_shared_key_no_password();
	test_generate_shared_key_with_password();
	puts("Success: suite_key_storage_generate");
}


void test_generate_key_pair_no_password() {
	// TODO
}


void test_generate_key_pair_with_password() {
	// TODO
}


void test_generate_shared_key_no_password() {
	// setup
	ss_shared_key key1, key2, key3, key4;
	ss_error error, error1, error2, error3, error4;
	unsigned char counter3, counter4;
	unsigned char expected_value[SS_PUBLIC_KEY_LENGTH];

	for(size_t i = 0; i < sizeof expected_value; i++)
		expected_value[i] = i;

	// action
	error = ss_generate_shared_key(NULL, NULL);
	error1 = ss_generate_shared_key(&key1, NULL);
	error2 = ss_generate_shared_key(&key2, NULL);

	internal_random = test_random;
	error3 = ss_generate_shared_key(&key3, NULL);
	counter3 = test_random_counter;
	test_random_counter = 0;
	error4 = ss_generate_shared_key(&key4, "");
	counter4 = test_random_counter;
	internal_random = randombytes_buf;

	// verify
	assert(error == SS_ERROR_NULL_ARGUMENT);
	assert(error1 == SS_SUCCESS);
	assert(error2 == SS_SUCCESS);
	assert(error3 == SS_SUCCESS);
	assert(error4 == SS_SUCCESS);
	assert(!ss_shared_key_has_password(NULL));
	assert(key1.key_info.version == 0);
	assert(!ss_shared_key_has_password(&key2));
	assert(key3.key_info.version == 0);
	assert(key4.key_info.version == 0);
	assert(memcmp(key1.value, key2.value, sizeof key1.value) != 0);
	assert(memcmp(key1.value, key3.value, sizeof key1.value) != 0);
	assert(memcmp(key3.value, expected_value, sizeof expected_value) == 0);
	assert(memcmp(key3.value, key4.value, sizeof key3.value) == 0);
	assert(counter3 == SS_SHARED_KEY_LENGTH);
	assert(counter4 == SS_SHARED_KEY_LENGTH);
}


void test_generate_shared_key_with_password() {
	// TODO
}
