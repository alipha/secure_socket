#include "test.h"
#include "../key_storage.h"
#include "../secure_socket.h"
#include "../impl.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
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
	puts("\ttest_generate_key_pair_no_password");

	// setup
	ss_key_pair key1, key2, key3, key4, key5;
	ss_error error, error1, error2, error3, error4, error5;
	unsigned char counter3, counter4, counter5;
	unsigned char expected_private_key[SS_PRIVATE_KEY_LENGTH];
	unsigned char expected_private_key5[SS_PRIVATE_KEY_LENGTH];
	unsigned char expected_public_key[] = {143, 64, 197, 173, 182, 143, 37, 98, 74, 229, 178, 20, 234, 118, 122, 110, 201, 77, 130, 157, 61, 123, 94, 26, 209, 186, 111, 62, 33, 56, 40, 95};
	unsigned char expected_public_key5[] = {7, 163, 124, 188, 20, 32, 147, 200, 183, 85, 220, 27, 16, 232, 108, 180, 38, 55, 74, 209, 106, 168, 83, 237, 11, 223, 192, 178, 184, 109, 28, 124};

	for(size_t i = 0; i < sizeof expected_private_key; i++) {
		expected_private_key[i] = i;
		expected_private_key5[i] = i + 1;
	}

	// action
	internal_random = randombytes_buf;
	error = ss_generate_key_pair(NULL, NULL);
	error1 = ss_generate_key_pair(&key1, NULL);
	error2 = ss_generate_key_pair(&key2, NULL);

	internal_random = test_random;
	test_random_counter = 0;
	error3 = ss_generate_key_pair(&key3, NULL);
	counter3 = test_random_counter;
	test_random_counter = 0;
	error4 = ss_generate_key_pair(&key4, "");
	counter4 = test_random_counter;
	test_random_counter = 1;
	error5 = ss_generate_key_pair(&key5, NULL);
	counter5 = test_random_counter;
	test_random_counter = 0;
	internal_random = randombytes_buf;

	/*
	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key3.public_key.value[i]);
	printf("\n");

	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key5.public_key.value[i]);
	printf("\n");
	*/	

	// verify
	assert(error == SS_ERROR_NULL_ARGUMENT);
	assert(error1 == SS_SUCCESS);
	assert(error2 == SS_SUCCESS);
	assert(error3 == SS_SUCCESS);
	assert(error4 == SS_SUCCESS);
	assert(error5 == SS_SUCCESS);
	assert(!ss_private_key_has_password(NULL));
	assert(key1.private_key_info.version == 0);
	assert(!ss_private_key_has_password(&key2));
	assert(key3.private_key_info.version == 0);
	assert(key4.private_key_info.version == 0);
	assert(memcmp(key1.public_key.value, key2.public_key.value, sizeof key1.public_key.value) != 0);
	assert(memcmp(key1.public_key.value, key3.public_key.value, sizeof key1.public_key.value) != 0);
	assert(memcmp(key3.public_key.value, expected_public_key, sizeof expected_public_key) == 0);
	assert(memcmp(key3.public_key.value, key4.public_key.value, sizeof key3.public_key.value) == 0);
	assert(memcmp(key5.public_key.value, expected_public_key5, sizeof expected_public_key5) == 0);
	assert(memcmp(key1.private_key, key2.private_key, sizeof key1.private_key) != 0);
	assert(memcmp(key1.private_key, key3.private_key, sizeof key1.private_key) != 0);
	assert(memcmp(key3.private_key, expected_private_key, sizeof expected_private_key) == 0);
	assert(memcmp(key3.private_key, key4.private_key, sizeof key3.private_key) == 0);
	assert(memcmp(key5.private_key, expected_private_key5, sizeof expected_private_key5) == 0);
	assert(counter3 == SS_SHARED_KEY_LENGTH);
	assert(counter4 == SS_SHARED_KEY_LENGTH);
	assert(counter5 == SS_SHARED_KEY_LENGTH + 1);
	assert(sizeof expected_public_key == SS_PUBLIC_KEY_LENGTH);
	assert(sizeof expected_public_key5 == SS_PUBLIC_KEY_LENGTH);
}


void test_generate_key_pair_with_password() {
	// TODO
	puts("\ttest_generate_key_pair_with_password");
}


void test_generate_shared_key_no_password() {
	puts("\ttest_generate_shared_key_no_password");

	// setup
	ss_shared_key key1, key2, key3, key4;
	ss_error error, error1, error2, error3, error4;
	unsigned char counter3, counter4;
	unsigned char expected_value[SS_SHARED_KEY_LENGTH];

	for(size_t i = 0; i < sizeof expected_value; i++)
		expected_value[i] = i;

	// action
	internal_random = randombytes_buf;
	error = ss_generate_shared_key(NULL, NULL);
	error1 = ss_generate_shared_key(&key1, NULL);
	error2 = ss_generate_shared_key(&key2, NULL);

	internal_random = test_random;
	test_random_counter = 0;
	error3 = ss_generate_shared_key(&key3, NULL);
	counter3 = test_random_counter;
	test_random_counter = 0;
	error4 = ss_generate_shared_key(&key4, "");
	counter4 = test_random_counter;
	test_random_counter = 0;
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
	puts("\ttest_generate_shared_key_with_password");
}
