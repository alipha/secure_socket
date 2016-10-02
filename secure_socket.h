#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include "common.h"

#define SS_PUBLIC_KEY_LENGTH 32U
#define SS_PRIVATE_KEY_LENGTH 32U
#define SS_SHARED_KEY_LENGTH 32U

#define SS_KEY_SALT_LENGTH 16U
#define SS_KEY_VERIFICATION_LENGTH 16U


typedef struct ss_settings {
	uint32_t password_iterations;
	uint32_t password_memory;
} ss_settings;


typedef struct ss_key_derivation_info {
	uint32_t version;
	uint32_t iterations;
	uint32_t memory;
	unsigned char salt[SS_KEY_SALT_LENGTH];
	unsigned char verification[SS_KEY_VERIFICATION_LENGTH];
} ss_key_derivation_info;


typedef struct ss_public_key {
	unsigned char value[SS_PUBLIC_KEY_LENGTH];
} ss_public_key;


typedef struct ss_key_pair {
	ss_public_key public_key;
	unsigned char private_key[SS_PRIVATE_KEY_LENGTH];
	ss_key_derivation_info private_key_info;
} ss_key_pair;


typedef struct ss_shared_key {
	unsigned char value[SS_SHARED_KEY_LENGTH];
	ss_key_derivation_info key_info;
} ss_shared_key;


typedef struct secure_socket {
	int socket;
	uint32_t state;
	handshake_hello my_hello;
	handshake_hello their_hello;
	ss_shared_key shared_key;
	unsigned char master_private_key[PRIVATE_KEY_LENGTH];
	unsigned char ephemeral_private_key[PRIVATE_KEY_LENGTH];
	unsigned char nonce[NONCE_LENGTH];
	uint32_t ephemeral_key_id;
	unsigned char my_new_ephemeral_public_key[PUBLIC_KEY_LENGTH];
	unsigned char my_new_ephemeral_private_key[PRIVATE_KEY_LENGTH];
	unsigned char their_new_ephemeral_public_key[PUBLIC_KEY_LENGTH];
	uint32_t bytes_read;
	message_frame *current_input_frame;
} secure_socket;



ss_error ss_generate_key_pair(ss_key_pair *key_pair, const char *private_key_password);
ss_error ss_generate_shared_key(ss_shared_key *shared_key, const char *password);

secure_socket* ss_socket(const ss_key_pair *my_key_pair);



#endif
