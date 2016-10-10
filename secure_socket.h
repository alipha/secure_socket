#ifndef SECURE_SOCKET_H
#define SECURE_SOCKET_H

#include "common.h"

#define SS_PUBLIC_KEY_LENGTH  32U
#define SS_PRIVATE_KEY_LENGTH 32U
#define SS_SHARED_KEY_LENGTH  32U


#define SS_KEY_SALT_LENGTH 16U
#define SS_KEY_VERIFICATION_LENGTH 16U

#define SS_ENCRYPTED_PRIVATE_KEY_LENGTH (SS_KEY_VERIFICATION_LENGTH + SS_PRIVATE_KEY_LENGTH)
#define SS_ENCRYPTED_SHARED_KEY_LENGTH (SS_KEY_VERIFICATION_LENGTH + SS_SHARED_KEY_LENGTH)


// internal
#define SS_ENCODED_RAW_PRIVATE_KEY_LENGTH ((SS_PRIVATE_KEY_LENGTH * 4 + 2) / 3)
#define SS_ENCODED_RAW_SECRET_KEY_LENGTH ((SS_SHARED_KEY_LENGTH * 4 + 2) / 3)
#define SS_ENCODED_RAW_ENCRYPTED_PRIVATE_KEY_LENGTH ((SS_ENCRYPTED_PRIVATE_KEY_LENGTH * 4 + 2) / 3)
#define SS_ENCODED_RAW_ENCRYPTED_SECRET_KEY_LENGTH ((SS_ENCRYPTED_SHARED_KEY_LENGTH * 4 + 2) / 3)
#define SS_ENCODED_KEY_SALT_LENGTH ((SS_KEY_SALT_LENGTH * 4 + 2) / 3)


// these exclude the nul character
#define SS_ENCODED_PUBLIC_KEY_LENGTH ((SS_PUBLIC_KEY_LENGTH * 4 + 2) / 3)
// public_key:0:key or public_key:1:IIIIII:MMMMMM:salt:encrypted_key
#define SS_ENCODED_KEY_PAIR_MIN_LENGTH   (3 + SS_ENCODED_PUBLIC_KEY_LENGTH + SS_ENCODED_RAW_PRIVATE_KEY_LENGTH)
#define SS_ENCODED_KEY_PAIR_MAX_LENGTH   (18 + SS_ENCODED_PUBLIC_KEY_LENGTH + SS_ENCODED_KEY_SALT_LENGTH + SS_ENCODED_RAW_ENCRYPTED_PRIVATE_KEY_LENGTH) 
// 0:key or 1:IIIIII:MMMMMM:salt:encrypted_key
#define SS_ENCODED_SHARED_KEY_MIN_LENGTH (2 + SS_ENCODED_RAW_SECRET_KEY_LENGTH)
#define SS_ENCODED_SHARED_KEY_MAX_LENGTH (17 + SS_ENCODED_KEY_SALT_LENGTH + SS_ENCODED_RAW_ENCRYPTED_SECRET_KEY_LENGTH) 


typedef struct ss_settings {
	uint32_t password_iterations;
	uint32_t password_memory_kb;
} ss_settings;


typedef struct ss_key_derivation_info {
	uint32_t version;
	uint32_t iterations;
	uint32_t memory_kb;
	unsigned char salt[SS_KEY_SALT_LENGTH];
} ss_key_derivation_info;


typedef struct ss_public_key {
	unsigned char value[SS_PUBLIC_KEY_LENGTH];
} ss_public_key;


typedef struct ss_key_pair {
	ss_public_key public_key;
	ss_key_derivation_info private_key_info;
	unsigned char private_key[SS_PRIVATE_KEY_LENGTH];
	unsigned char encrypted_private_key[SS_ENCRYPTED_PRIVATE_KEY_LENGTH]; // stores a 16-byte verification token (argon2(password)[0..15]) followed by private_key[0..31] ^ argon2(password)[16..47]
} ss_key_pair;


typedef struct ss_shared_key {
	ss_key_derivation_info key_info;
	unsigned char value[SS_SHARED_KEY_LENGTH];
	unsigned char encrypted_value[SS_ENCRYPTED_SHARED_KEY_LENGTH]; // stores a 16-byte verification token (argon2(password)[0..15]) followed by private_key[0..31] ^ argon2(password)[16..47]
} ss_shared_key;


typedef struct secure_socket secure_socket;


void ss_get_settings(ss_settings *s);
void ss_set_settings(ss_settings *s);


secure_socket* ss_socket_init(const ss_key_pair *my_key_pair);  // my_key_pair may be NULL

ss_error ss_shared_key_connect(secure_socket *sock, const char *host, int port, const ss_shared_key *shared_key);
ss_error ss_public_key_connect(secure_socket *sock, const char *host, int port, const ss_public_key *server_public_key);

ss_error ss_shared_key_listen(secure_socket *sock, int port, const ss_shared_key *shared_key);
ss_error ss_public_key_listen(secure_socket *sock, int port, const ss_public_key *client_public_keys, size_t key_count);

void ss_socket_free(secure_socket *sock);

#endif
