#include "test.h"
#include "../key_storage.h"
#include "../secure_socket.h"
#include "../impl.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>


void test_encode_public_key(void);
void test_encode_key_pair_no_password(void);
void test_encode_key_pair_with_password(void);
void test_encode_shared_key_no_password(void);
void test_encode_shared_key_with_password(void);


void suite_key_storage_encode(void) {
	puts("Start:   suite_key_storage_encode");
	test_encode_public_key();
	test_encode_key_pair_no_password();
	test_encode_key_pair_with_password();
	test_encode_shared_key_no_password();
	test_encode_shared_key_with_password();
	puts("Success: suite_key_storage_encode");
}


void test_encode_public_key(void) {
	puts("\ttest_encode_public_key");

	// setup
	char encoded1[SS_ENCODED_PUBLIC_KEY_LENGTH + 2] = "abc";
	char encoded2[SS_ENCODED_PUBLIC_KEY_LENGTH + 2] = "def";
	ss_public_key key1;
	ss_error error1, error2, error3, error4, error5, error6;
	int compare1, compare2;

	encoded1[SS_ENCODED_PUBLIC_KEY_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded1[SS_ENCODED_PUBLIC_KEY_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this
	encoded2[SS_ENCODED_PUBLIC_KEY_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded2[SS_ENCODED_PUBLIC_KEY_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this

	for(size_t i = 0; i < sizeof key1.value; i++)
		key1.value[i] = i * 2 + 1;

	// act
	error1 = ss_encode_public_key(NULL, sizeof encoded1 - 1, &key1);
	error2 = ss_encode_public_key(NULL, sizeof encoded1 - 1, NULL);
	error3 = ss_encode_public_key(encoded1, sizeof encoded1 - 1, NULL);
	compare1 = strcmp(encoded1, "abc");
	error4 = ss_encode_public_key(encoded1, sizeof encoded1 - 2, &key1);
	compare2 = strcmp(encoded1, "abc");
	error5 = ss_encode_public_key(encoded1, sizeof encoded1 - 1, &key1);
	error6 = ss_encode_public_key(encoded2, sizeof encoded2, &key1);

	// verify
	assert(error1 == SS_ERROR_NULL_ARGUMENT);
	assert(error2 == SS_ERROR_NULL_ARGUMENT);
	assert(error3 == SS_ERROR_NULL_ARGUMENT);
	assert(error4 == SS_ERROR_BUFFER_TOO_SMALL);
	assert(error5 == SS_SUCCESS);
	assert(error6 == SS_SUCCESS);
	assert(compare1 == 0);
	assert(compare2 == 0);
	assert(strcmp(encoded1, "AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(strcmp(encoded2, "AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(encoded1[SS_ENCODED_PUBLIC_KEY_LENGTH + 1] == 'y');
	assert(encoded2[SS_ENCODED_PUBLIC_KEY_LENGTH + 1] == 'y');
}


void test_encode_key_pair_no_password(void) {
	puts("\ttest_encode_key_pair_no_password");

	// setup
	char encoded1[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 2] = "abc";
	char encoded2[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 2] = "def";
	char encoded3[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 1];
	ss_key_pair key1, key3;
	ss_error error1, error2, error3, error4, error5, error6, error7, error8;
	int compare1, compare2;
	unsigned char counter7;

	encoded1[SS_ENCODED_KEY_PAIR_MIN_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded1[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this
	encoded2[SS_ENCODED_KEY_PAIR_MIN_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded2[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this

	key1.private_key_info.version = 0;

	for(size_t i = 0; i < sizeof key1.private_key; i++)
		key1.private_key[i] = i * 2 + 1;

	for(size_t j = 0; j < sizeof key1.public_key.value; j++)
		key1.public_key.value[j] = j * 3;

	// act
	error1 = ss_encode_key_pair(NULL, sizeof encoded1 - 1, &key1);
	error2 = ss_encode_key_pair(NULL, sizeof encoded1 - 1, NULL);
	error3 = ss_encode_key_pair(encoded1, sizeof encoded1 - 1, NULL);
	compare1 = strcmp(encoded1, "abc");
	error4 = ss_encode_key_pair(encoded1, sizeof encoded1 - 2, &key1);
	compare2 = strcmp(encoded1, "abc");
	error5 = ss_encode_key_pair(encoded1, sizeof encoded1 - 1, &key1);
	error6 = ss_encode_key_pair(encoded2, sizeof encoded2, &key1);

	internal_random = test_random;
	test_random_counter = 0;
	error7 = ss_generate_key_pair(&key3, NULL);
	counter7 = test_random_counter;
	test_random_counter = 0;
	internal_random = randombytes_buf;
	error8 = ss_encode_key_pair(encoded3, sizeof encoded3, &key3);

	// verify
	assert(error1 == SS_ERROR_NULL_ARGUMENT);
	assert(error2 == SS_ERROR_NULL_ARGUMENT);
	assert(error3 == SS_ERROR_NULL_ARGUMENT);
	assert(error4 == SS_ERROR_BUFFER_TOO_SMALL);
	assert(error5 == SS_SUCCESS);
	assert(error6 == SS_SUCCESS);
	assert(error7 == SS_SUCCESS);
	assert(error8 == SS_SUCCESS);
	assert(compare1 == 0);
	assert(compare2 == 0);
	assert(counter7 == SS_PRIVATE_KEY_LENGTH);
	assert(strcmp(encoded1, "AAMGCQwPEhUYGx4hJCcqLTAzNjk8P0JFSEtOUVRXWl0:0:AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(strcmp(encoded2, "AAMGCQwPEhUYGx4hJCcqLTAzNjk8P0JFSEtOUVRXWl0:0:AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(strcmp(encoded3, "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8:0:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") == 0);
	assert(encoded1[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 1] == 'y');
	assert(encoded2[SS_ENCODED_KEY_PAIR_MIN_LENGTH + 1] == 'y');
}


void test_encode_key_pair_with_password(void) {
	// TODO
	puts("\ttest_encode_key_pair_with_password");
}


void test_encode_shared_key_no_password(void) {
	puts("\ttest_encode_shared_key_no_password");
	
	// setup
	char encoded1[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 2] = "abc";
	char encoded2[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 2] = "def";
	char encoded3[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 1];
	ss_shared_key key1, key3;
	ss_error error1, error2, error3, error4, error5, error6, error7, error8;
	int compare1, compare2;
	unsigned char counter7;

	encoded1[SS_ENCODED_SHARED_KEY_MIN_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded1[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this
	encoded2[SS_ENCODED_SHARED_KEY_MIN_LENGTH] = 'x';  // ensure terminating nul overwrites this
	encoded2[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 1] = 'y';  // ensure terminating nul does not overwrite this

	key1.key_info.version = 0;

	for(size_t i = 0; i < sizeof key1.value; i++)
		key1.value[i] = i * 2 + 1;

	// act
	error1 = ss_encode_shared_key(NULL, sizeof encoded1 - 1, &key1);
	error2 = ss_encode_shared_key(NULL, sizeof encoded1 - 1, NULL);
	error3 = ss_encode_shared_key(encoded1, sizeof encoded1 - 1, NULL);
	compare1 = strcmp(encoded1, "abc");
	error4 = ss_encode_shared_key(encoded1, sizeof encoded1 - 2, &key1);
	compare2 = strcmp(encoded1, "abc");
	error5 = ss_encode_shared_key(encoded1, sizeof encoded1 - 1, &key1);
	error6 = ss_encode_shared_key(encoded2, sizeof encoded2, &key1);

	internal_random = test_random;
	test_random_counter = 0;
	error7 = ss_generate_shared_key(&key3, NULL);
	counter7 = test_random_counter;
	test_random_counter = 0;
	internal_random = randombytes_buf;
	error8 = ss_encode_shared_key(encoded3, sizeof encoded3, &key3);

	// verify
	assert(error1 == SS_ERROR_NULL_ARGUMENT);
	assert(error2 == SS_ERROR_NULL_ARGUMENT);
	assert(error3 == SS_ERROR_NULL_ARGUMENT);
	assert(error4 == SS_ERROR_BUFFER_TOO_SMALL);
	assert(error5 == SS_SUCCESS);
	assert(error6 == SS_SUCCESS);
	assert(error7 == SS_SUCCESS);
	assert(error8 == SS_SUCCESS);
	assert(compare1 == 0);
	assert(compare2 == 0);
	assert(counter7 == SS_SHARED_KEY_LENGTH);
	assert(strcmp(encoded1, "0:AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(strcmp(encoded2, "0:AQMFBwkLDQ8RExUXGRsdHyEjJScpKy0vMTM1Nzk7PT8") == 0);
	assert(strcmp(encoded3, "0:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") == 0);
	assert(encoded1[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 1] == 'y');
	assert(encoded2[SS_ENCODED_SHARED_KEY_MIN_LENGTH + 1] == 'y');
}


void test_encode_shared_key_with_password(void) {
	// TODO
	puts("\ttest_encode_shared_key_with_password");
}

