#include "impl.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <netdb.h>

// not using libsodium's constants directly because if there were any changes to
// them, that would break the protocol
#if EPHEMERAL_PUBLIC_KEY_LENGTH != crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#error "EPHEMERAL_PUBLIC_KEY_LENGTH does not match libsodium's crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES"
#endif

#if EPHEMERAL_PRIVATE_KEY_LENGTH != crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#error "EPHEMERAL_PRIVATE_KEY_LENGTH does not match libsodium's crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES"
#endif

#if SIGNATURE_LENGTH != crypto_sign_ed25519_BYTES
#error "SIGNATURE_LENGTH does not match libsodium's crypto_sign_ed25519_BYTES"
#endif

#if TAG_LENGTH != crypto_aead_chacha20poly1305_ABYTES
#error "TAG_LENGTH does not match libsodium's crypto_aead_chacha20poly1305_ABYTES"
#endif

#if NONCE_LENGTH != crypto_aead_chacha20poly1305_NPUBBYTES
#error "NONCE_LENGTH does not match libsodium's crypto_aead_chacha20poly1305_NPUBBYTES"
#endif


void (*ss_random)(void * const buf, const size_t size) = randombytes_buf;
int (*ss_sign_keypair)(unsigned char *, unsigned char *) = crypto_sign_ed25519_keypair;

void* (* volatile ss_memset)(void *, int, size_t) = memset;

void* (*ss_malloc)(size_t) = malloc;
void (*ss_malloc_free)(void *) = free;

int (*ss_internal_close)(int) = close;
int (*ss_internal_socket)(int, int, int) = socket;
int (*ss_internal_connect)(int, const struct sockaddr *, socklen_t) = connect;

int (*ss_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = getaddrinfo;
void (*ss_freeaddrinfo)(struct addrinfo *) = freeaddrinfo;


void ss_sign_message(unsigned char *signature, const void *message, size_t message_len, const ss_key_pair *key_pair) {
	unsigned char combined_key[COMBINED_KEY_LENGTH];

	assert(signature != NULL);
	assert(message != NULL);
	assert(key_pair != NULL);

	memcpy(combined_key, key_pair->private_key, sizeof key_pair->private_key);
	memcpy(combined_key + sizeof key_pair->private_key, key_pair->public_key.value, sizeof key_pair->public_key.value);

	crypto_sign_ed25519_detached(signature, NULL, message, message_len, combined_key);
	ss_memset(combined_key, 0, sizeof combined_key);
}


BOOL ss_verify_signature(const unsigned char *signature, const void *message, size_t message_len, ss_public_key *public_key) {
	assert(signature != NULL);
	assert(message != NULL);
	assert(public_key != NULL);

	return crypto_sign_ed25519_verify_detached(signature, message, message_len, public_key->value) == 0;
}


void increment_nonce_by_2(unsigned char *nonce) {
	nonce[NONCE_LENGTH - 1] += 2;

	if(nonce[NONCE_LENGTH - 1] > 1)	// there was no wrap around (carry-over)
		return;

	for(int i = NONCE_LENGTH - 2; i >= 0; i--) {  // wrap around should never happen in practical usage
		nonce[i]++;
		if(nonce[i] > 0)
			return;
	}
}


void binary_write(unsigned char **output, const void *input, size_t amount) {
	memcpy(*output, input, amount);
	*output += amount;
}


BOOL binary_read(void *output, const unsigned char **input, const unsigned char *end_ptr, size_t amount) {
	assert(output != NULL);
	assert(input != NULL);
	assert(*input != NULL);
	assert(end_ptr > *input);

	BOOL has_room = !end_ptr || ((size_t)(end_ptr - *input) >= amount);
	if(!has_room)
		amount = end_ptr - *input;

	memcpy(output, *input, amount);
	*input += amount;
	return has_room;
}


void uint32_write(unsigned char **output, uint32_t value) {
	value = htonl(value);
	binary_write(output, &value, sizeof value);
}


BOOL uint32_read(uint32_t *value, const unsigned char **input, const unsigned char *end_ptr) {
	assert(value != NULL);
	assert(input != NULL);
	assert(*input != NULL);

	if(binary_read(value, input, end_ptr, sizeof *value)) {
		*value = ntohl(*value);
		return TRUE;
	}

	return FALSE;
}


size_t pack_header(unsigned char *output, const message_header *header) {
	assert(output != NULL);
	assert(header != NULL);

	unsigned char *ptr = output;

	uint32_write(&ptr, header->length);
	uint32_write(&ptr, header->message_type);
	uint32_write(&ptr, header->status);
	uint32_write(&ptr, header->provided_fields);

	return ptr - output;
}


ss_error unpack_header(message_header *header, const unsigned char **input) {
	assert(header != NULL);
	assert(input != NULL);
	assert(*input != NULL);

	uint32_read(&header->length, input, NULL);
	if(header->length < MESSAGE_HEADER_LENGTH)
		return STATUS_ERROR | STATUS_INVALID_LENGTH;

	// TODO: return STATUS_UNKNOWN_MESSAGE_TYPE and STATUS_UNKNOWN_STATUS
	uint32_read(&header->message_type, input, NULL);
	uint32_read(&header->status, input, NULL);
	uint32_read(&header->provided_fields, input, NULL);

	return STATUS_GOOD;
}


size_t pack_hello(unsigned char *output, const handshake_hello *hello) {
	assert(output != NULL);
	assert(hello != NULL);

	unsigned char *ptr = output;
	uint32_t fields = hello->header.provided_fields;

	ptr += pack_header(ptr, &hello->header);

	if(fields & PROVIDED_VERSION)
		uint32_write(&ptr, hello->version);

	if(fields & PROVIDED_MIN_VERSION)
		uint32_write(&ptr, hello->min_version);

	if(fields & PROVIDED_SESSION_TOKEN_TIMEOUT)
		uint32_write(&ptr, hello->token_timeout_seconds);

	if(fields & PROVIDED_SESSION_TOKEN_LENGTH)
		uint32_write(&ptr, hello->session_token_length);

	if(fields & PROVIDED_SESSION_TOKEN)
		binary_write(&ptr, hello->session_token, sizeof hello->session_token);

	if(fields & PROVIDED_EPHEMERAL_KEY_LENGTH)
		uint32_write(&ptr, hello->ephemeral_key_length);

	if(fields & PROVIDED_EPHEMERAL_PUBLIC_KEY)
		binary_write(&ptr, hello->ephemeral_public_key, sizeof hello->ephemeral_public_key);

	if(fields & PROVIDED_MASTER_KEY_LENGTH)
		uint32_write(&ptr, hello->master_key_length);

	if(fields & PROVIDED_MASTER_PUBLIC_KEY)
		binary_write(&ptr, hello->master_public_key, sizeof hello->master_public_key);

	if(fields & PROVIDED_NONCE_LENGTH)
		uint32_write(&ptr, hello->nonce_length);

	if(fields & PROVIDED_SIGNATURE_LENGTH)
		uint32_write(&ptr, hello->signature_length);

	if(fields & PROVIDED_TAG_LENGTH)
		uint32_write(&ptr, hello->tag_length);

	size_t handshake_length = ptr - output;
	uint32_write(&output, handshake_length);	// rewrite the message_header.length with the true length
	return handshake_length;
}


ss_error unpack_hello(handshake_hello *hello, const unsigned char **input, const unsigned char *end_ptr) {
	assert(hello != NULL);
	assert(input != NULL);
	assert(*input != NULL);
	assert(end_ptr != NULL);
	assert(end_ptr > *input);

	uint32_t fields;
	ss_error error;
	BOOL invalid_length = FALSE;

	if((size_t)(end_ptr - *input) < MESSAGE_HEADER_LENGTH)
		return STATUS_ERROR | STATUS_INVALID_LENGTH;

	error = unpack_header(&hello->header, input);
	if(error & STATUS_ERROR)
		return error;

	error = 0;
	fields = hello->header.provided_fields;

	if(fields & PROVIDED_VERSION)
		invalid_length |= uint32_read(&hello->version, input, end_ptr);

	if(fields & PROVIDED_MIN_VERSION) {
		invalid_length |= uint32_read(&hello->min_version, input, end_ptr);

		if(!invalid_length && hello->min_version > 1)
			return STATUS_ERROR | STATUS_VERSION_TOO_HIGH;
	}

	if(fields & PROVIDED_SESSION_TOKEN_TIMEOUT)
		invalid_length |= uint32_read(&hello->token_timeout_seconds, input, end_ptr);

	if(fields & PROVIDED_SESSION_TOKEN_LENGTH)
		invalid_length |= uint32_read(&hello->session_token_length, input, end_ptr);

	if(fields & PROVIDED_SESSION_TOKEN)
		invalid_length |= binary_read(hello->session_token, input, end_ptr, sizeof hello->session_token);

	if(fields & PROVIDED_EPHEMERAL_KEY_LENGTH) {
		invalid_length |= uint32_read(&hello->ephemeral_key_length, input, end_ptr);

		if(!invalid_length && hello->ephemeral_key_length != sizeof hello->ephemeral_public_key)
			return error | STATUS_ERROR | STATUS_INVALID_EPHEMERAL_KEY_LENGTH;
	}

	if(fields & PROVIDED_EPHEMERAL_PUBLIC_KEY)
		invalid_length |= binary_read(hello->ephemeral_public_key, input, end_ptr, sizeof hello->ephemeral_public_key);

	if(fields & PROVIDED_MASTER_KEY_LENGTH) {
		invalid_length |= uint32_read(&hello->master_key_length, input, end_ptr);

		if(!invalid_length && hello->master_key_length != sizeof hello->master_public_key)
			return error | STATUS_ERROR | STATUS_INVALID_MASTER_KEY_LENGTH;
	}

	if(fields & PROVIDED_MASTER_PUBLIC_KEY)
		invalid_length |= binary_read(hello->master_public_key, input, end_ptr, sizeof hello->master_public_key);

	if(fields & PROVIDED_NONCE_LENGTH) {
		invalid_length |= uint32_read(&hello->nonce_length, input, end_ptr);

		if(!invalid_length && hello->nonce_length != NONCE_LENGTH)
			error |= STATUS_ERROR | STATUS_INVALID_NONCE_LENGTH;
	}

	if(fields & PROVIDED_SIGNATURE_LENGTH) {
		invalid_length |= uint32_read(&hello->signature_length, input, end_ptr);

		if(!invalid_length && hello->signature_length != SIGNATURE_LENGTH)
			error |= STATUS_ERROR | STATUS_INVALID_SIGNATURE_LENGTH;
	}

	if(fields & PROVIDED_TAG_LENGTH) {
		invalid_length |= uint32_read(&hello->tag_length, input, end_ptr);

		if(!invalid_length && hello->tag_length != TAG_LENGTH)
			error |= STATUS_ERROR | STATUS_INVALID_TAG_LENGTH;
	}

	if(invalid_length)
		error |= STATUS_ERROR | STATUS_INVALID_LENGTH;
 
	if(error)
		return error;

	return STATUS_GOOD;
}

