#include "test.h"
#include "../key_storage.h"
#include "../secure_socket.h"
#include "../impl.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>


static void test_generate_key_pair_no_password(void);
static void test_generate_key_pair_with_password(void);
static void test_key_pair_can_sign_and_verify(void);
static void test_generate_shared_key_no_password(void);
static void test_generate_shared_key_with_password(void);


void suite_key_storage_generate() {
	puts("Start:   suite_key_storage_generate");
	test_generate_key_pair_no_password();
	test_generate_key_pair_with_password();
	test_key_pair_can_sign_and_verify();
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
	unsigned char expected_public_key[] = {3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184};
	unsigned char expected_public_key5[] = {121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100};

	for(size_t i = 0; i < sizeof expected_private_key; i++) {
		expected_private_key[i] = i;
		expected_private_key5[i] = i + 1;
	}

	// action
	ss_sign_keypair = crypto_sign_ed25519_keypair;
	error = ss_generate_key_pair(NULL, NULL);
	error1 = ss_generate_key_pair(&key1, NULL);
	error2 = ss_generate_key_pair(&key2, NULL);

	ss_sign_keypair = test_sign_keypair;
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
	ss_sign_keypair = crypto_sign_ed25519_keypair;

	/*
printf("Public keys:\n");
	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key3.public_key.value[i]);
	printf("\n");

	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key5.public_key.value[i]);
	printf("\n");
	
printf("Private keys:\n");
	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key3.private_key[i]);
	printf("\n");

	for(size_t i = 0; i < sizeof expected_public_key; i++)
		printf("%d, ", key5.private_key[i]);
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


void test_key_pair_can_sign_and_verify() {
	puts("\ttest_key_pair_can_sign_and_verify");

	// setup
	const char *msg_a = "Hello, this magnificant world!";
	const char *msg_b = "hello, this magnificant world!";

	unsigned char sig1[SIGNATURE_LENGTH];
	unsigned char sig1_again[SIGNATURE_LENGTH + 1];
	unsigned char sig2[SIGNATURE_LENGTH];
	unsigned char sig3[SIGNATURE_LENGTH];
	unsigned char sig1b[SIGNATURE_LENGTH];

	ss_key_pair key1, key2, key3;
	ss_error error1, error2;

	sig1_again[SIGNATURE_LENGTH] = 'x';

	error1 = ss_generate_key_pair(&key1, NULL);
	error2 = ss_generate_key_pair(&key2, NULL);
	memcpy(&key3, &key1, sizeof key1);
	memcpy(&key3.public_key, &key2.public_key, sizeof key2.public_key);

	// act
	ss_sign_message(sig1, msg_a, strlen(msg_a), &key1);
	ss_sign_message(sig1_again, msg_a, strlen(msg_a), &key1);
	ss_sign_message(sig2, msg_a, strlen(msg_a), &key2);
	ss_sign_message(sig3, msg_a, strlen(msg_a), &key3);
	ss_sign_message(sig1b, msg_b, strlen(msg_b), &key1);

	// verify
	assert(error1 == SS_SUCCESS);
	assert(error2 == SS_SUCCESS);
	assert(sig1_again[SIGNATURE_LENGTH] == 'x');
	assert(memcmp(sig1, sig1_again, sizeof sig1) == 0);
	assert(memcmp(sig1, sig2, sizeof sig1) != 0);
	assert(memcmp(sig1, sig3, sizeof sig1) != 0);
	assert(memcmp(sig1, sig1b, sizeof sig1) != 0);
	assert(memcmp(sig2, sig3, sizeof sig2) != 0);
	assert(ss_verify_signature(sig1, msg_a, strlen(msg_a), &key1.public_key));
	assert(ss_verify_signature(sig2, msg_a, strlen(msg_a), &key2.public_key));
	assert(!ss_verify_signature(sig3, msg_a, strlen(msg_a), &key3.public_key));
	assert(!ss_verify_signature(sig3, msg_a, strlen(msg_a), &key1.public_key));
	assert(ss_verify_signature(sig1b, msg_b, strlen(msg_b), &key1.public_key));
	assert(!ss_verify_signature(sig1, msg_b, strlen(msg_b), &key1.public_key));
	assert(!ss_verify_signature(sig2, msg_a, strlen(msg_a), &key1.public_key));
	assert(!ss_verify_signature(sig1, msg_a, sizeof msg_a, &key1.public_key));
		
	// TODO: test with encrypted keys
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
	ss_random = randombytes_buf;
	error = ss_generate_shared_key(NULL, NULL);
	error1 = ss_generate_shared_key(&key1, NULL);
	error2 = ss_generate_shared_key(&key2, NULL);

	ss_random = test_random;
	test_random_counter = 0;
	error3 = ss_generate_shared_key(&key3, NULL);
	counter3 = test_random_counter;
	test_random_counter = 0;
	error4 = ss_generate_shared_key(&key4, "");
	counter4 = test_random_counter;
	test_random_counter = 0;
	ss_random = randombytes_buf;

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
