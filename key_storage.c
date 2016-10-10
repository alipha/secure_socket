#include "key_storage.h"
#include "impl.h"
#include "base64.h"
#include <sodium.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>


static BOOL decode_base64(void *dest, size_t dest_len, const char **encoded);

static ss_error encode_secret_key(char *encoded, size_t encoded_max, const ss_key_derivation_info *key_info, const unsigned char *secret_key, size_t key_len);
static ss_error decode_secret_key(ss_key_derivation_info *key_info, unsigned char *key, size_t key_len, unsigned char *encrypted_key, unsigned char *verification_and_xor_stream, const char *encoded, const char *password);

static ss_error encrypt_secret_key(unsigned char *verification_and_encrypted_key, ss_key_derivation_info *key_info, const char *password, unsigned char *secret_key, size_t key_len);



ss_error ss_generate_key_pair(ss_key_pair *key_pair, const char *private_key_password) {
	ss_error error;
	unsigned char public_key[sizeof key_pair->public_key.value];
	unsigned char combined_key[sizeof key_pair->private_key + sizeof key_pair->public_key.value];

	if(!key_pair)
		return SS_ERROR_NULL_ARGUMENT;

	// libsodium's crypto_sign_ed25519_seed_keypair redundantly puts the public key in the first half of combined_key, so only the first half is secret
	ss_sign_keypair(public_key, combined_key);

	error = encrypt_secret_key(key_pair->encrypted_private_key, &key_pair->private_key_info, private_key_password, combined_key, sizeof key_pair->private_key);

	if(error) {
		ss_memset(combined_key, 0, sizeof combined_key);
		return error;
	}

	memcpy(key_pair->public_key.value, public_key, sizeof public_key);
	memcpy(key_pair->private_key, combined_key, sizeof key_pair->private_key);

	ss_memset(combined_key, 0, sizeof combined_key);
	return SS_SUCCESS;
}


ss_error ss_generate_shared_key(ss_shared_key *shared_key, const char *password) {
	ss_error error;
	unsigned char secret_key[sizeof shared_key->value];

	if(!shared_key)
		return SS_ERROR_NULL_ARGUMENT;

	ss_random(secret_key, sizeof secret_key);

	error = encrypt_secret_key(shared_key->encrypted_value, &shared_key->key_info, password, secret_key, sizeof secret_key);

	if(error) {
		ss_memset(secret_key, 0, sizeof secret_key);
		return error;
	}

	memcpy(shared_key->value, secret_key, sizeof secret_key);

	ss_memset(secret_key, 0, sizeof secret_key);
	return SS_SUCCESS;
}



ss_error ss_encode_public_key(char *encoded, size_t encoded_max, const ss_public_key *public_key) {
	if(!encoded || !public_key)
		return SS_ERROR_NULL_ARGUMENT;

	if(encoded_max <= SS_ENCODED_PUBLIC_KEY_LENGTH)
		return SS_ERROR_BUFFER_TOO_SMALL;
	
	ss_to_base64(encoded, encoded_max, public_key->value, sizeof public_key->value);
	return SS_SUCCESS;
}


ss_error ss_encode_key_pair(char *encoded, size_t encoded_max, const ss_key_pair *key_pair) {
	BOOL encrypted = FALSE;
	const unsigned char *secret_key;
	size_t key_len;

	if(!encoded || !key_pair)
		return SS_ERROR_NULL_ARGUMENT;

	secret_key = key_pair->private_key;
	key_len = sizeof key_pair->private_key;

	if(key_pair->private_key_info.version > 0) {
		encrypted = TRUE;
		secret_key = key_pair->encrypted_private_key;
		key_len = sizeof key_pair->encrypted_private_key;
	}

	if(encoded_max <= SS_ENCODED_KEY_PAIR_MIN_LENGTH || (encrypted && encoded_max <= SS_ENCODED_KEY_PAIR_MAX_LENGTH))
		return SS_ERROR_BUFFER_TOO_SMALL;

	ss_encode_public_key(encoded, encoded_max, &key_pair->public_key);

	encoded += SS_ENCODED_PUBLIC_KEY_LENGTH;
	*encoded++ = ':';

	return encode_secret_key(encoded, encoded_max - SS_ENCODED_PUBLIC_KEY_LENGTH - 1, &key_pair->private_key_info, secret_key, key_len);
}


ss_error ss_encode_shared_key(char *encoded, size_t encoded_max, const ss_shared_key *shared_key) {
	BOOL encrypted = FALSE;
	const unsigned char *secret_key;
	size_t key_len;

	if(!encoded || !shared_key)
		return SS_ERROR_NULL_ARGUMENT;

	secret_key = shared_key->value;
	key_len = sizeof shared_key->value;

	if(shared_key->key_info.version > 0) {
		encrypted = TRUE;
		secret_key = shared_key->encrypted_value;
		key_len = sizeof shared_key->encrypted_value;
	}

	if(encoded_max <= SS_ENCODED_SHARED_KEY_MIN_LENGTH || (encrypted && encoded_max <= SS_ENCODED_SHARED_KEY_MAX_LENGTH))
		return SS_ERROR_BUFFER_TOO_SMALL;

	return encode_secret_key(encoded, encoded_max, &shared_key->key_info, secret_key, key_len);	
}



ss_error ss_decode_public_key(ss_public_key *public_key, const char *encoded) {
	unsigned char raw_bytes[sizeof public_key->value];

	if(!public_key || !encoded)
		return SS_ERROR_NULL_ARGUMENT;

	if(!decode_base64(raw_bytes, sizeof raw_bytes, &encoded))
		return SS_ERROR_BAD_ENCODED_FORMAT;

	memcpy(public_key->value, raw_bytes, sizeof raw_bytes);
	ss_memset(raw_bytes, 0, sizeof raw_bytes);
	return SS_SUCCESS;
}


ss_error ss_decode_key_pair(ss_key_pair *key_pair, const char *encoded, const char *private_key_password) {
	ss_key_pair result;
	unsigned char verification_and_xor_stream[sizeof result.encrypted_private_key];
	ss_error error;

	if(!key_pair || !encoded)
		return SS_ERROR_NULL_ARGUMENT;

	error = ss_decode_public_key(&result.public_key, encoded);

	if(error)
		return error;

	encoded += SS_ENCODED_PUBLIC_KEY_LENGTH;

	if(*encoded != ':')
		return SS_ERROR_BAD_ENCODED_FORMAT;

	error = decode_secret_key(&result.private_key_info, result.private_key, sizeof result.private_key, result.encrypted_private_key, verification_and_xor_stream, encoded + 1, private_key_password);
	ss_memset(verification_and_xor_stream, 0, sizeof verification_and_xor_stream);

	if(error)
		return error;

	*key_pair = result;
	ss_memset(&result, 0, sizeof result);
	return SS_SUCCESS;
}


ss_error ss_decode_shared_key(ss_shared_key *shared_key, const char *encoded, const char *password) {
	ss_shared_key result;
	unsigned char verification_and_xor_stream[sizeof result.encrypted_value];
	ss_error error;

	if(!shared_key || !encoded)
		return SS_ERROR_NULL_ARGUMENT;

	error = decode_secret_key(&result.key_info, result.value, sizeof result.value, result.encrypted_value, verification_and_xor_stream, encoded, password);
	ss_memset(verification_and_xor_stream, 0, sizeof verification_and_xor_stream);

	if(error)
		return error;

	*shared_key = result;
	ss_memset(&result, 0, sizeof result);
	return SS_SUCCESS;
}


BOOL ss_private_key_has_password(ss_key_pair *key_pair) {
	return key_pair && key_pair->private_key_info.version;
}

BOOL ss_shared_key_has_password(ss_shared_key *shared_key) {
	return shared_key && shared_key->key_info.version;
}

ss_error ss_change_private_key_password(ss_key_pair *key_pair, const char *new_password) {
	if(!key_pair)
		return SS_ERROR_NULL_ARGUMENT;

	return encrypt_secret_key(key_pair->encrypted_private_key, &key_pair->private_key_info, new_password, key_pair->private_key, sizeof key_pair->private_key);
}

ss_error ss_change_shared_key_password(ss_shared_key *shared_key, const char *new_password) {
	if(!shared_key)
		return SS_ERROR_NULL_ARGUMENT;
	
	return encrypt_secret_key(shared_key->encrypted_value, &shared_key->key_info, new_password, shared_key->value, sizeof shared_key->value);
}



BOOL decode_base64(void *dest, size_t dest_len, const char **encoded) {
	assert(dest != NULL);
	assert(encoded != NULL);

	size_t expected_base64_len = (dest_len * 4 + 2) / 3;
	const char *end_ptr = ss_from_base64(dest, &dest_len, *encoded);

	*encoded = end_ptr;

	if(end_ptr && dest_len == expected_base64_len)
		return TRUE;

	ss_memset(dest, 0, dest_len);
	return FALSE;
}


ss_error encode_secret_key(char *encoded, size_t encoded_max, const ss_key_derivation_info *key_info, const unsigned char *secret_key, size_t key_len) {
	assert(encoded != NULL);
	assert(key_info != NULL);
	assert(secret_key != NULL);

	const char *encoded_end = encoded + encoded_max;
	uint32_t iterations = htonl(key_info->iterations);
	uint32_t memory_kb = htonl(key_info->memory_kb);

	// if not encrypted
	if(key_info->version == 0) {
		*encoded++ = '0';
		*encoded++ = ':';
		ss_to_base64(encoded, encoded_end - encoded, secret_key, key_len);
		return SS_SUCCESS;
	}

	*encoded++ = '1';
	*encoded++ = ':';
	encoded += ss_to_base64(encoded, encoded_end - encoded, &iterations, sizeof iterations);
	*encoded++ = ':';
	encoded += ss_to_base64(encoded, encoded_end - encoded, &memory_kb, sizeof memory_kb);
	*encoded++ = ':';
	encoded += ss_to_base64(encoded, encoded_end - encoded, key_info->salt, sizeof key_info->salt);
	*encoded++ = ':';
	ss_to_base64(encoded, encoded_end - encoded, secret_key, key_len);
	return SS_SUCCESS;
}


ss_error decode_secret_key(ss_key_derivation_info *key_info, unsigned char *key, size_t key_len, unsigned char *encrypted_key, unsigned char *verification_and_xor_stream, const char *encoded, const char *password) {
	ss_key_derivation_info info_result;
	uint32_t iterations;
	uint32_t memory_kb;
	size_t encrypted_key_len = SS_KEY_VERIFICATION_LENGTH + key_len;

	assert(key_info != NULL);
	assert(key != NULL);
	assert(encrypted_key != NULL);
	assert(verification_and_xor_stream != NULL);
	assert(encoded != NULL);

	if((encoded[0] != '0' && encoded[0] != '1') || encoded[1] != ':')
		return SS_ERROR_BAD_ENCODED_FORMAT;

	info_result.version = encoded[0] - '0';
	encoded += 2;

	// if not encrypted
	if(info_result.version == 0) {
		// should this error if a password is provided?

		if(!decode_base64(key, key_len, &encoded))
			return SS_ERROR_BAD_ENCODED_FORMAT;

		*key_info = info_result;
		return SS_SUCCESS;
	}


	if(!password || !password[0])
		return SS_ERROR_INVALID_PASSWORD;

	if(!decode_base64(&iterations, sizeof iterations, &encoded) || *encoded != ':'
			|| !decode_base64(&memory_kb, sizeof memory_kb, &encoded) || *encoded != ':' 
			|| !decode_base64(info_result.salt, sizeof info_result.salt, &encoded) || *encoded != ':'
			|| !decode_base64(encrypted_key, encrypted_key_len, &encoded))
		return SS_ERROR_BAD_ENCODED_FORMAT;

	info_result.iterations = ntohl(iterations);
	info_result.memory_kb = ntohl(memory_kb);


	if(crypto_pwhash_argon2i(verification_and_xor_stream, encrypted_key_len, password, strlen(password), info_result.salt, info_result.iterations, info_result.memory_kb << 10, crypto_pwhash_ALG_ARGON2I13) != 0)
		return SS_ERROR_OUT_OF_MEMORY;

	if(!memcmp(verification_and_xor_stream, encrypted_key, SS_KEY_VERIFICATION_LENGTH))
		return SS_ERROR_INVALID_PASSWORD;

	memcpy(key, encrypted_key + SS_KEY_VERIFICATION_LENGTH, key_len);
	xor_bytes(key, verification_and_xor_stream + SS_KEY_VERIFICATION_LENGTH, key_len);

	*key_info = info_result;
	return SS_SUCCESS;
}


ss_error encrypt_secret_key(unsigned char *verification_and_encrypted_key, ss_key_derivation_info *key_info, const char *password, unsigned char *secret_key, size_t key_len) {

	unsigned char salt[sizeof key_info->salt];
	ss_settings settings;

	assert(verification_and_encrypted_key != NULL);
	assert(key_info != NULL);
	assert(secret_key != NULL);

	// if password is not provided
	if(!password || !password[0]) {
		key_info->version = 0;
		return SS_SUCCESS;
	}

	ss_get_settings(&settings);
	ss_random(salt, sizeof salt);


	if(crypto_pwhash_argon2i(verification_and_encrypted_key, SS_KEY_VERIFICATION_LENGTH + key_len, password, strlen(password), salt, settings.password_iterations, settings.password_memory_kb << 10, crypto_pwhash_ALG_ARGON2I13) != 0)
		return SS_ERROR_OUT_OF_MEMORY;

	key_info->version = 1;
	key_info->iterations = settings.password_iterations;
	key_info->memory_kb = settings.password_memory_kb;

	memcpy(key_info->salt, salt, sizeof salt);
	xor_bytes(verification_and_encrypted_key + SS_KEY_VERIFICATION_LENGTH, secret_key, key_len);
	return SS_SUCCESS;
}

